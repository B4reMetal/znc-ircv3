/*
 * chathistory — draft/chathistory and draft/event-playback for ZNC.
 *
 * Global module (caps must be offered at CAP LS time). Keeps a persistent,
 * lossless message store per user/network/target and answers CHATHISTORY
 * queries from it. Clients that negotiate draft/chathistory no longer get
 * ZNC's automatic buffer playback on attach; they fetch what they need.
 *
 *   caps     draft/chathistory, draft/event-playback
 *   ISUPPORT CHATHISTORY=<limit> MSGREFTYPES=timestamp,msgid
 *   commands CHATHISTORY LATEST|BEFORE|AFTER|AROUND|BETWEEN|TARGETS
 *            SEARCH in=;from=;after=;before=;text=;limit= (soju.im/search:
 *            case-insensitive substring over PRIVMSG/NOTICE text, one target
 *            or, without in=, every target of the network; results oldest
 *            first in a soju.im/search batch; the cap is withdrawn on
 *            unbound connections). Answered from a per-user SQLite FTS5
 *            index (common/searchindex.h) kept in step with the day files:
 *            live lines are inserted as they are stored, a background job
 *            indexes files that changed on disk (at load, hourly, and on the
 *            `sync` / `reindex` commands). Day files the index does not
 *            cover yet are scanned directly within a line/time budget; when
 *            anything was cut short the client gets
 *            NOTE SEARCH TRUNCATED :Results may be incomplete first.
 *   batch    chathistory <target>, draft/chathistory-targets
 *   replies  FAIL CHATHISTORY INVALID_PARAMS|INVALID_TARGET|MESSAGE_ERROR|NEED_MORE_PARAMS
 *
 * Store layout (under the module's data dir):
 *   <user>/<network>/<target>/<YYYY-MM-DD>.log   one full IRC line per message,
 *                                                tags kept (time, msgid, client tags)
 *   <user>/<network>/<target>/latest             timestamp of the newest message
 * Events (JOIN/PART/QUIT/KICK/MODE/TOPIC/NICK/TAGMSG) are stored with a
 * znc.in/event tag and only returned when event-playback is enabled.
 *
 * Also implements draft/message-redaction: upstream REDACT lines remove
 * the message from the store and from ZNC's playback buffer and are
 * forwarded to clients that negotiated the cap; a client REDACT is
 * forwarded when the upstream supports it and refused otherwise.
 *
 * Module args: days=<retention, default 90> limit=<max per request, default 1000>
 *              searchlines=<fallback scan budget, lines> searchms=<fallback scan
 *              and index query budget, milliseconds>
 */
#include <znc/Modules.h>
#include <znc/Chan.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/Query.h>
#include <znc/Nick.h>
#include <znc/User.h>
#include <znc/Utils.h>
#include <znc/znc.h>

#include "caps.h"
#include "clients.h"
#include "ids.h"
#include "isupport.h"
#include "msgtag.h"
#include "replies.h"
#include "searchindex.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <vector>

namespace fs = std::filesystem;
using ircv3::CapTracker;
using ircv3::PutFail;
using ircv3::PutNote;
using ircv3::SearchIndex;

namespace {
const char* kCap = "draft/chathistory";
const char* kCapEvents = "draft/event-playback";
const char* kCapRedact = "draft/message-redaction";
const char* kEventTag = "znc.in/event";
const char* kCmd = "CHATHISTORY";
const char* kCapSearch = "soju.im/search";
const char* kSearchCmd = "SEARCH";
const char* kSearchBatch = "soju.im/search";
const char* kStandardReplies = "standard-replies";
// Default budget for scanning day files the index does not cover (and for
// one index query): a broad pattern over a large store must not stall ZNC.
const size_t kSearchMaxLines = 400000;
const long kSearchMaxMillis = 2000;
const char* kIndexFile = ".search.db";

bool IsTimestamp(const CString& s) {
    if (s.size() != 24 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != '.' || s[23] != 'Z')
        return false;
    for (size_t i = 0; i < 23; i++) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) continue;
        if (!isdigit((unsigned char)s[i])) return false;
    }
    return true;
}

// A stored message with the fields queries need.
struct Entry {
    CString sTime;   // 2026-10-12T17:00:00.000Z
    CString sMsgId;  // may be empty
    bool bEvent = false;
    CString sLine;   // full line with tags
};

struct Selector {
    enum Kind { None, Time, MsgId } kind = None;
    CString sValue;
};

bool ParseSelector(const CString& s, Selector& sel) {
    if (s.StartsWith("timestamp=")) {
        sel.sValue = s.substr(10);
        if (!IsTimestamp(sel.sValue)) return false;
        sel.kind = Selector::Time;
        return true;
    }
    if (s.StartsWith("msgid=")) {
        sel.sValue = s.substr(6);
        if (sel.sValue.empty()) return false;
        sel.kind = Selector::MsgId;
        return true;
    }
    return false;
}

// Target names become directory names: lowercase, unsafe bytes %XX-encoded.
CString SafeName(const CString& sTarget) {
    CString out;
    for (unsigned char c : sTarget.AsLower()) {
        if (isalnum(c) || c == '#' || c == '&' || c == '+' || c == '!' || c == '-' || c == '_' || c == '[' || c == ']' ||
            c == '{' || c == '}' || c == '|' || c == '^' || c == '`' || c == '\\')
            out += (char)c;
        else {
            char buf[4];
            snprintf(buf, sizeof buf, "%%%02X", c);
            out += buf;
        }
    }
    if (out.empty() || out[0] == '.') out = "%2E" + out;
    return out;
}

std::vector<CString> DayFiles(const fs::path& dir) {
    std::vector<CString> v;
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return v;
    for (const auto& de : fs::directory_iterator(dir, ec)) {
        CString name = de.path().filename().string();
        if (name.size() == 14 && name.EndsWith(".log")) v.push_back(name.substr(0, 10));
    }
    std::sort(v.begin(), v.end());
    return v;
}

fs::path DayPath(const fs::path& dir, const CString& sDay) { return dir / (sDay.c_str() + CString(".log")).c_str(); }

// The index row for a stored line; false for events and non-messages.
bool MakeRow(const CString& sLine, const CString& sNet, const CString& sTarget, const CString& sDay, long long lOff,
             long long lLen, ircv3::IndexRow& r) {
    CMessage m(sLine);
    if (m.GetTags().count(kEventTag)) return false;
    const CString& sCmd = m.GetCommand();
    if (!sCmd.Equals("PRIVMSG") && !sCmd.Equals("NOTICE")) return false;
    r.sNetwork = sNet;
    r.sTarget = sTarget;
    r.sDay = sDay;
    r.sTime = m.GetTag("time");
    r.sNick = m.GetNick().GetNick().AsLower();
    r.sMsgId = m.GetTag("msgid");
    r.lOff = lOff;
    r.lLen = lLen;
    r.sText = ircv3::StripFormatting(m.GetParam(1));
    return true;
}

// (Re)indexes one day file whole, replacing whatever the index had for it.
bool IndexDayFile(SearchIndex& idx, const fs::path& file, const CString& sNet, const CString& sTarget,
                  const CString& sDay) {
    std::error_code ec;
    long long lSize = (long long)fs::file_size(file, ec);
    if (ec) return false;
    std::vector<ircv3::IndexRow> rows;
    std::ifstream f(file, std::ios::binary);
    std::string line;
    long long lOff = 0;
    while (std::getline(f, line)) {
        long long lLen = (long long)line.size() + 1;
        ircv3::IndexRow r;
        if (!line.empty() && MakeRow(line, sNet, sTarget, sDay, lOff, lLen, r)) rows.push_back(std::move(r));
        lOff += lLen;
    }
    return idx.ReplaceDay(sNet, sTarget, sDay, rows, lSize);
}

CString ReadLineAt(const fs::path& file, long long lOff, long long lLen) {
    if (lLen <= 0 || lLen > 1 << 20) return "";
    std::ifstream f(file, std::ios::binary);
    f.seekg(lOff);
    std::string s((size_t)lLen, '\0');
    f.read(&s[0], lLen);
    s.resize((size_t)f.gcount());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}
}  // namespace

class CChatHistory;

// Walks every user's store in a worker thread and indexes the day files
// whose size differs from what the index recorded (new, grown, rewritten),
// dropping records of files that are gone. Each user is a separate
// database; the thread uses its own connections.
class CSyncJob : public CModuleJob {
  public:
    CSyncJob(CModule* pMod, const CString& sRoot, bool bFull)
        : CModuleJob(pMod, "chathistory-sync", "Index history for SEARCH"), m_sRoot(sRoot), m_bFull(bFull) {}

    void runThread() override {
        const auto t0 = std::chrono::steady_clock::now();
        std::error_code ec;
        fs::path root(m_sRoot.c_str());
        for (const auto& user : fs::directory_iterator(root, ec)) {
            CString sUser = user.path().filename().string();
            if (sUser.StartsWith(".") || !fs::is_directory(user.path(), ec)) continue;
            SearchIndex idx;
            CString sErr;
            if (!idx.Open((user.path() / kIndexFile).string(), sErr, 20000)) {
                m_sError += sUser + ": " + sErr + "; ";
                continue;
            }
            if (m_bFull) idx.ForgetDays();
            std::map<CString, long long> sizes = idx.DaySizes("");
            std::set<CString> seen;
            for (const auto& net : fs::directory_iterator(user.path(), ec)) {
                if (!fs::is_directory(net.path(), ec)) continue;
                const CString sNet = net.path().filename().string();
                for (const auto& target : fs::directory_iterator(net.path(), ec)) {
                    if (!fs::is_directory(target.path(), ec)) continue;
                    const CString sTarget = target.path().filename().string();
                    for (const CString& sDay : DayFiles(target.path())) {
                        if (wasCancelled()) return;
                        const CString sKey = SearchIndex::DayKey(sNet, sTarget, sDay);
                        seen.insert(sKey);
                        fs::path file = DayPath(target.path(), sDay);
                        long long lSize = (long long)fs::file_size(file, ec);
                        auto it = sizes.find(sKey);
                        if (!ec && it != sizes.end() && it->second == lSize) continue;
                        if (IndexDayFile(idx, file, sNet, sTarget, sDay)) { m_uFiles++; continue; }
                        if (IndexDayFile(idx, file, sNet, sTarget, sDay)) { m_uFiles++; continue; }  // once more (lock contention)
                        m_uErrors++;
                        if (m_vsFailed.size() < 5) m_vsFailed.push_back(sUser + "/" + sNet + "/" + sTarget + "/" + sDay + ": " + idx.LastError());
                    }
                }
            }
            for (const auto& kv : sizes) {
                if (seen.count(kv.first)) continue;
                VCString parts;
                kv.first.Split("\n", parts, true);
                if (parts.size() == 3 && idx.DeleteDay(parts[0], parts[1], parts[2])) m_uRemoved++;
            }
            m_lRows += idx.CountRows();
        }
        m_lMillis = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    }
    void runMain() override;

    CString m_sRoot;
    bool m_bFull;
    unsigned m_uFiles = 0, m_uRemoved = 0, m_uErrors = 0;
    long long m_lRows = 0, m_lMillis = 0;
    CString m_sError;
    VCString m_vsFailed;
};

class CChatHistory : public CModule {
  public:
    MODCONSTRUCTOR(CChatHistory) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "chathistory must be loaded as a global module";
            return false;
        }
        VCString vsArgs;
        sArgs.Split(" ", vsArgs, false);
        for (const CString& s : vsArgs) {
            if (s.StartsWith("days=")) m_uDays = CString(s.substr(5)).ToUInt();
            else if (s.StartsWith("limit=")) m_uLimit = CString(s.substr(6)).ToUInt();
            else if (s.StartsWith("searchlines=")) m_uSearchMaxLines = CString(s.substr(12)).ToULong();
            else if (s.StartsWith("searchms=")) m_lSearchMaxMillis = CString(s.substr(9)).ToLong();
            else { sMessage = "Unknown argument " + s + " (use days=N limit=N searchlines=N searchms=N)"; return false; }
        }
        if (m_uLimit == 0) m_uLimit = 1000;
        if (m_uSearchMaxLines == 0) m_uSearchMaxLines = kSearchMaxLines;
        if (m_lSearchMaxMillis <= 0) m_lSearchMaxMillis = kSearchMaxMillis;
        std::error_code ec;
        fs::create_directories(GetSavePath().c_str(), ec);
        Prune();
        // Open (and, if the schema changed, recreate) every existing user's
        // index here, on the main thread, before the sync job can touch it.
        for (const auto& user : fs::directory_iterator(GetSavePath().c_str(), ec)) {
            const CString sUserDir = user.path().filename().string();
            if (!sUserDir.StartsWith(".") && fs::is_directory(user.path(), ec)) IndexForDir(sUserDir);
        }
        AddTimer(PruneTimer, "prune", 3600, 0, "Prune old history and sync the search index");
        StartSync(false);
        return true;
    }

    // ---- search index ---------------------------------------------------

    // One connection per user, opened on first use. A failed open is
    // remembered (and shown by `status`); searches then scan the files.
    SearchIndex* IndexForDir(const CString& sUserDir) {
        auto it = m_mIndexes.find(sUserDir);
        if (it != m_mIndexes.end()) {
            if (it->second) return it->second.get();
            if (time(nullptr) < m_mIndexRetry[sUserDir]) return nullptr;  // failed recently; try again later
        }
        std::error_code ec;
        fs::path dir = fs::path(GetSavePath().c_str()) / sUserDir.c_str();
        fs::create_directories(dir, ec);
        auto pIdx = std::make_unique<SearchIndex>();
        CString sErr;
        // Short busy timeout: the main thread must not wait on the sync job.
        if (!pIdx->Open((dir / kIndexFile).string(), sErr, 250, true)) {
            DEBUG("chathistory: search index for " << sUserDir << " unavailable: " << sErr);
            m_mIndexErrors[sUserDir] = sErr;
            m_mIndexes[sUserDir] = nullptr;
            m_mIndexRetry[sUserDir] = time(nullptr) + 15;
            return nullptr;
        }
        m_mIndexErrors.erase(sUserDir);
        return (m_mIndexes[sUserDir] = std::move(pIdx)).get();
    }
    SearchIndex* IndexFor(const CUser* pUser) { return IndexForDir(SafeName(pUser->GetUsername())); }

    void StartSync(bool bFull) {
        if (m_bSyncing) { m_bSyncPending = true; m_bSyncPendingFull |= bFull; return; }
        m_bSyncing = true;
        m_bIndexReady = false;
        AddJob(new CSyncJob(this, GetSavePath(), bFull));
    }

    void OnSyncDone(const CSyncJob& job) {
        m_bSyncing = false;
        m_bIndexReady = job.m_uErrors == 0 && job.m_sError.empty();
        m_sSyncReport = CString(job.m_uFiles) + " day files indexed, " + CString(job.m_uRemoved) + " dropped, " +
                        CString(job.m_lRows) + " messages, " + CString(job.m_lMillis) + " ms";
        if (job.m_uErrors) {
            m_sSyncReport += ", " + CString(job.m_uErrors) + " files failed";
            for (const CString& f : job.m_vsFailed) m_sSyncReport += " [" + f + "]";
        }
        if (!job.m_sError.empty()) m_sSyncReport += ", " + job.m_sError;
        DEBUG("chathistory: sync done: " << m_sSyncReport);
        if (m_bSyncPending) {
            m_bSyncPending = false;
            bool bFull = m_bSyncPendingFull;
            m_bSyncPendingFull = false;
            StartSync(bFull);
        }
    }

    // ---- caps / ISUPPORT ------------------------------------------------

    static bool IsOurCap(const CString& sCap) {
        return sCap.Equals(kCap) || sCap.Equals(kCapEvents) || sCap.Equals(kCapRedact) || sCap.Equals(kCapSearch);
    }
    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(kCap);
        ssCaps.insert(kCapEvents);
        ssCaps.insert(kCapRedact);
        ssCaps.insert(kCapSearch);
    }
    bool IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState) override { return IsOurCap(sCap); }
    void OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) override {
        if (IsOurCap(sCap) || sCap.Equals(kStandardReplies)) m_Caps.Set(pClient, sCap, bState);
    }
    bool OnServerCap302Available(const CString& sCap, const CString& sValue) override {
        return sCap.Equals(kCapRedact);
    }
    void OnClientDisconnect() override {
        m_Caps.Forget(GetClient());
        m_Burst.Forget(GetClient());
        m_mSearchWithdrawn.Erase(GetClient());
        m_mLoggedIn.Erase(GetClient());
    }

    // soju.im/search only makes sense on a connection bound to a network:
    // withdrawn (CAP DEL) on an unbound connection, offered again (CAP NEW)
    // when the client attaches to a network. Runs from OnClientLogin, after
    // bouncernetworks has applied the binding.
    void SyncSearchCap(CClient* pClient) {
        if (!pClient) return;
        bool* pWithdrawn = m_mSearchWithdrawn.Find(pClient);
        if (!pClient->GetNetwork()) {
            if (m_Caps.Has(pClient, kCapSearch) && !(pWithdrawn && *pWithdrawn)) {
                m_Caps.Set(pClient, kCapSearch, false);
                m_mSearchWithdrawn[pClient] = true;
                pClient->NotifyServerDependentCap(kCapSearch, false, "");
            }
        } else if (pWithdrawn && *pWithdrawn) {
            *pWithdrawn = false;
            pClient->NotifyServerDependentCap(kCapSearch, true, "");
        }
    }
    void OnClientLogin() override {
        if (GetClient()) m_mLoggedIn[GetClient()] = true;
        SyncSearchCap(GetClient());
    }

    // REDACT only reaches clients that asked for it. ISUPPORT tokens go
    // inside the registration burst; the upstream's own CHATHISTORY tokens
    // are dropped since this module answers the command.
    EModRet OnSendToClientMessage(CMessage& Message) override {
        if (Message.GetCommand().Equals("REDACT") && !m_Caps.Has(Message.GetClient(), kCapRedact)) return HALT;
        return m_Burst.OnSend(Message, [this](CClient* p) { return ISupportFor(p); });
    }

    void OnClientAttached() override {
        m_Burst.OnAttached(GetClient(), [this](CClient* p) { return ISupportFor(p); });
        // Attach events before OnClientLogin happen inside bouncernetworks'
        // binding, where output to the client is swallowed; wait for login.
        if (GetClient() && m_mLoggedIn.Has(GetClient())) SyncSearchCap(GetClient());
    }

    // Clients with chathistory fetch history themselves.
    EModRet OnChanBufferPlayMessage(CMessage& Message) override {
        return m_Caps.Has(Message.GetClient(), kCap) ? HALT : CONTINUE;
    }
    EModRet OnPrivBufferPlayMessage(CMessage& Message) override {
        return m_Caps.Has(Message.GetClient(), kCap) ? HALT : CONTINUE;
    }

    // ---- store writers --------------------------------------------------

    // Server-to-client messages: the target is the channel or, for queries,
    // the sender's nick.
    EModRet OnChanTextMessage(CTextMessage& M) override { Store(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnChanActionMessage(CActionMessage& M) override { Store(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnChanNoticeMessage(CNoticeMessage& M) override { Store(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnChanTagMessage(CTargetMessage& M) override { Store(M, M.GetTarget(), true); return CONTINUE; }
    EModRet OnPrivTextMessage(CTextMessage& M) override { Store(M, M.GetNick().GetNick(), false); return CONTINUE; }
    EModRet OnPrivActionMessage(CActionMessage& M) override { Store(M, M.GetNick().GetNick(), false); return CONTINUE; }
    EModRet OnPrivNoticeMessage(CNoticeMessage& M) override { Store(M, M.GetNick().GetNick(), false); return CONTINUE; }
    EModRet OnPrivTagMessage(CTargetMessage& M) override { Store(M, M.GetNick().GetNick(), true); return CONTINUE; }

    // The user's own messages (echoed by ZNC to other clients).
    EModRet OnUserTextMessage(CTextMessage& M) override { StoreOwn(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnUserActionMessage(CActionMessage& M) override { StoreOwn(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnUserNoticeMessage(CNoticeMessage& M) override { StoreOwn(M, M.GetTarget(), false); return CONTINUE; }
    EModRet OnUserTagMessage(CTargetMessage& M) override { StoreOwn(M, M.GetTarget(), true); return CONTINUE; }

    // Events.
    void OnJoinMessage(CJoinMessage& M) override { Store(M, M.GetTarget(), true); }
    void OnPartMessage(CPartMessage& M) override { Store(M, M.GetTarget(), true); }
    void OnKickMessage(CKickMessage& M) override { Store(M, M.GetTarget(), true); }
    EModRet OnTopicMessage(CTopicMessage& M) override { Store(M, M.GetTarget(), true); return CONTINUE; }
    void OnQuitMessage(CQuitMessage& M, const std::vector<CChan*>& vChans) override {
        for (CChan* pChan : vChans) Store(M, pChan->GetName(), true);
    }
    void OnNickMessage(CNickMessage& M, const std::vector<CChan*>& vChans) override {
        for (CChan* pChan : vChans) Store(M, pChan->GetName(), true);
    }
    EModRet OnRawMessage(CMessage& M) override {
        // Channel MODE changes are not exposed through a typed hook with
        // the channel; take them here.
        if (M.GetType() == CMessage::Type::Mode && GetNetwork()) {
            CString sTarget = M.GetParam(0);
            if (GetNetwork()->FindChan(sTarget)) Store(M, sTarget, true);
        }
        if (M.GetCommand().Equals("REDACT") && GetNetwork()) {
            // :nick REDACT <target> <msgid> [:reason]
            CString sTarget = M.GetParam(0), sMsgId = M.GetParam(1);
            if (GetNetwork()->IsChan(sTarget) == false && !M.GetNick().GetNick().empty() &&
                !M.GetNick().NickEquals(GetNetwork()->GetCurNick()))
                sTarget = M.GetNick().GetNick();  // a query: stored under the peer's nick
            Redact(GetNetwork(), sTarget, sMsgId);
        }
        return CONTINUE;
    }

    // ---- CHATHISTORY ----------------------------------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return CONTINUE;
        if (Message.GetCommand().Equals("REDACT")) {
            CIRCNetwork* pNet = pClient->GetNetwork();
            CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
            if (!pSock || !pSock->IsCapAccepted(kCapRedact)) {
                PutFail(pClient, "REDACT", "REDACT_FORBIDDEN",
                        {Message.GetParam(0).empty() ? "*" : Message.GetParam(0),
                         Message.GetParam(1).empty() ? "*" : Message.GetParam(1)},
                        "The server does not support message redaction");
                return HALT;
            }
            return CONTINUE;  // forwarded; the server echoes REDACT back
        }
        if (Message.GetCommand().Equals(kSearchCmd)) {
            HandleSearch(pClient, Message);
            return HALT;
        }
        if (!Message.GetCommand().Equals(kCmd)) return CONTINUE;
        HandleQuery(pClient, Message);
        return HALT;
    }

    void OnModCommand(const CString& sCommand) override {
        CString sCmd = sCommand.Token(0);
        if (sCmd.Equals("STATUS")) {
            PutModule("Retention " + (m_uDays == 0 ? CString("unlimited (days=0)") : CString(m_uDays) + " days") +
                      ", limit " + CString(m_uLimit) + " messages per request, store " + GetSavePath());
            PutModule("Search index: " + IndexStatus(GetUser()) + "; fallback scan budget " + CString(m_uSearchMaxLines) +
                      " lines / " + CString(m_lSearchMaxMillis) + " ms");
            if (CIRCNetwork* pNet = GetNetwork()) {
                CTable t;
                t.AddColumn("Target");
                t.AddColumn("Latest");
                for (const auto& kv : Targets(pNet, "", "~")) {
                    t.AddRow();
                    t.SetCell("Target", kv.first);
                    t.SetCell("Latest", kv.second);
                }
                PutModule(t);
            }
        } else if (sCmd.Equals("PRUNE")) {
            Prune();
            PutModule("Pruned history older than " + CString(m_uDays) + " days");
        } else if (sCmd.Equals("SYNC") || sCmd.Equals("REINDEX")) {
            StartSync(sCmd.Equals("REINDEX"));
            PutModule(m_bSyncPending ? "Index sync queued behind the running one" : "Index sync started in the background; see status");
        } else {
            PutModule("Commands: status, prune, sync (index files changed on disk), reindex (rebuild the search index)");
        }
    }

    CString IndexStatus(const CUser* pUser) {
        if (!pUser) return "(no user)";
        const CString sDir = SafeName(pUser->GetUsername());
        SearchIndex* pIdx = IndexForDir(sDir);
        if (!pIdx) return "unavailable (" + m_mIndexErrors[sDir] + ")";
        std::error_code ec;
        long long lBytes = (long long)fs::file_size(pIdx->Path().c_str(), ec);
        CString s = CString(pIdx->CountRows()) + " messages, " + CString(lBytes / 1048576) + " MB, schema " +
                    CString(pIdx->SchemaVersion()) + ", " + (m_bSyncing ? "syncing" : m_bIndexReady ? "ready" : "not synced");
        if (!m_sSyncReport.empty()) s += " (last sync: " + m_sSyncReport + ")";
        return s;
    }

  private:
    // ---- paths ----------------------------------------------------------

    fs::path NetDir(const CIRCNetwork* pNet) const {
        return fs::path(GetSavePath().c_str()) / SafeName(pNet->GetUser()->GetUsername()).c_str() /
               SafeName(pNet->GetName()).c_str();
    }
    fs::path TargetDir(const CIRCNetwork* pNet, const CString& sTarget) const {
        return NetDir(pNet) / SafeName(sTarget).c_str();
    }

    // ---- writing --------------------------------------------------------

    void StoreOwn(CMessage& M, const CString& sTarget, bool bEvent) {
        CIRCNetwork* pNet = M.GetNetwork() ? M.GetNetwork() : GetNetwork();
        if (!pNet || sTarget.empty()) return;
        if (sTarget.StartsWith(pNet->GetUser()->GetStatusPrefix())) return;
        CMessage copy(M);
        copy.SetNick(pNet->GetIRCNick());
        Store(copy, sTarget, bEvent);
    }

    void Store(CMessage& M, const CString& sTarget, bool bEvent) {
        CIRCNetwork* pNet = M.GetNetwork() ? M.GetNetwork() : GetNetwork();
        if (!pNet || sTarget.empty()) return;
        CMessage copy(M);
        MCString tags;
        for (const auto& kv : M.GetTags()) {
            if (kv.first == "batch" || kv.first == "time" || kv.first == kEventTag) continue;
            tags[kv.first] = kv.second;
        }
        tags["time"] = CUtils::FormatServerTime(M.GetTime());
        if (bEvent) tags[kEventTag] = "";
        copy.SetTags(tags);
        const CString sLine = copy.ToString();
        const CString sDay = tags["time"].substr(0, 10);

        std::error_code ec;
        fs::path dir = TargetDir(pNet, sTarget);
        fs::create_directories(dir, ec);
        fs::path file = DayPath(dir, sDay);
        long long lOff = (long long)fs::file_size(file, ec);
        if (ec) lOff = 0;
        {
            std::ofstream f(file, std::ios::app);
            f << sLine << "\n";
        }
        std::ofstream l(dir / "latest", std::ios::trunc);
        l << tags["time"] << "\n";
        std::ofstream n(dir / "name", std::ios::trunc);
        n << sTarget << "\n";

        if (SearchIndex* pIdx = IndexFor(pNet->GetUser())) {
            const CString sNetDir = SafeName(pNet->GetName()), sTargetDir = SafeName(sTarget);
            const long long lLen = (long long)sLine.size() + 1;
            ircv3::IndexRow r;
            // A write the busy sync job blocks is dropped; the recorded size
            // then stays behind the file and the next sync re-reads the day.
            bool bOk = !MakeRow(sLine, sNetDir, sTargetDir, sDay, lOff, lLen, r) || pIdx->Insert(r);
            if (bOk) pIdx->BumpDay(sNetDir, sTargetDir, sDay, lLen, lOff == 0);
        }
    }

    // ---- redaction ------------------------------------------------------

    void Redact(CIRCNetwork* pNet, const CString& sTarget, const CString& sMsgId) {
        if (sMsgId.empty()) return;
        // Store: rewrite the day file that holds the message.
        fs::path dir = TargetDir(pNet, sTarget);
        std::vector<CString> days = DayFiles(dir);
        for (auto it = days.rbegin(); it != days.rend(); ++it) {
            std::vector<Entry> v = ReadDay(dir, *it);
            size_t before = v.size();
            v.erase(std::remove_if(v.begin(), v.end(), [&](const Entry& e) { return e.sMsgId == sMsgId; }), v.end());
            if (v.size() == before) continue;
            {
                std::ofstream f(DayPath(dir, *it), std::ios::trunc);
                for (const Entry& e : v) f << e.sLine << "\n";
            }
            if (SearchIndex* pIdx = IndexFor(pNet->GetUser()))
                IndexDayFile(*pIdx, DayPath(dir, *it), SafeName(pNet->GetName()), SafeName(sTarget), *it);
            break;
        }
        // Playback buffer: rebuild without the line (the API has no remove).
        if (CChan* pChan = pNet->FindChan(sTarget)) {
            RebuildBuffer(pChan->GetBuffer(), sMsgId,
                          [&](const CMessage& m, const CString& t) { pChan->AddBuffer(m, t); },
                          [&]() { pChan->ClearBuffer(); });
        } else if (CQuery* pQuery = pNet->FindQuery(sTarget)) {
            RebuildBuffer(pQuery->GetBuffer(), sMsgId,
                          [&](const CMessage& m, const CString& t) { pQuery->AddBuffer(m, t); },
                          [&]() { pQuery->ClearBuffer(); });
        }
    }

    template <typename Add, typename Clear>
    static void RebuildBuffer(const CBuffer& Buffer, const CString& sMsgId, Add add, Clear clear) {
        bool bFound = false;
        std::vector<std::pair<CMessage, CString>> keep;
        for (size_t i = 0; i < Buffer.Size(); i++) {
            const CBufLine& line = Buffer.GetBufLine(i);
            auto t = line.GetTags().find("msgid");
            if (t != line.GetTags().end() && t->second == sMsgId) { bFound = true; continue; }
            CMessage m(line.GetFormat());
            m.SetTags(line.GetTags());
            m.SetTime(line.GetTime());
            keep.emplace_back(m, line.GetText());
        }
        if (!bFound) return;
        clear();
        for (const auto& kv : keep) add(kv.first, kv.second);
    }

    // ---- reading --------------------------------------------------------

    static Entry ParseEntry(const CString& sLine) {
        CMessage m(sLine);
        Entry e;
        e.sTime = m.GetTag("time");
        e.sMsgId = m.GetTag("msgid");
        e.bEvent = m.GetTags().count(kEventTag) == 1;
        e.sLine = sLine;
        return e;
    }

    // A day file is append-only and may hold lines out of order (live
    // messages and a later import of the same day), so sort on read by
    // time, then msgid.
    std::vector<Entry> ReadDay(const fs::path& dir, const CString& sDay) const {
        std::vector<Entry> v;
        std::ifstream f((dir / (sDay.c_str() + CString(".log")).c_str()));
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty()) v.push_back(ParseEntry(line));
        }
        std::stable_sort(v.begin(), v.end(), [](const Entry& a, const Entry& b) {
            return a.sTime != b.sTime ? a.sTime < b.sTime : a.sMsgId < b.sMsgId;
        });
        return v;
    }

    // Resolve a msgid selector to the message's timestamp (scanning newest
    // first). Returns false if unknown.
    bool FindMsgId(const fs::path& dir, const CString& sMsgId, CString& sTimeOut) const {
        std::vector<CString> days = DayFiles(dir);
        for (auto it = days.rbegin(); it != days.rend(); ++it) {
            for (const Entry& e : ReadDay(dir, *it))
                if (e.sMsgId == sMsgId) { sTimeOut = e.sTime; return true; }
        }
        return false;
    }

    // Messages with sFrom < time < sTo (exclusive bounds, empty = open),
    // newest first if bBackwards, up to uLimit.
    std::vector<Entry> Query(const fs::path& dir, const CString& sFrom, const CString& sTo, size_t uLimit,
                             bool bBackwards, bool bEvents, const CString& sExcludeId = "") const {
        std::vector<Entry> out;
        std::vector<CString> days = DayFiles(dir);
        auto accept = [&](const Entry& e) {
            if (!bEvents && e.bEvent) return false;
            if (!sFrom.empty() && e.sTime <= sFrom) return false;
            if (!sTo.empty() && e.sTime >= sTo) return false;
            if (!sExcludeId.empty() && e.sMsgId == sExcludeId) return false;
            return true;
        };
        if (bBackwards) {
            for (auto it = days.rbegin(); it != days.rend() && out.size() < uLimit; ++it) {
                if (!sFrom.empty() && *it < sFrom.substr(0, 10)) break;
                if (!sTo.empty() && *it > sTo.substr(0, 10)) continue;
                std::vector<Entry> day = ReadDay(dir, *it);
                for (auto e = day.rbegin(); e != day.rend() && out.size() < uLimit; ++e)
                    if (accept(*e)) out.push_back(*e);
            }
            std::reverse(out.begin(), out.end());  // deliver oldest first
        } else {
            for (auto it = days.begin(); it != days.end() && out.size() < uLimit; ++it) {
                if (!sFrom.empty() && *it < sFrom.substr(0, 10)) continue;
                if (!sTo.empty() && *it > sTo.substr(0, 10)) break;
                for (const Entry& e : ReadDay(dir, *it)) {
                    if (out.size() >= uLimit) break;
                    if (accept(e)) out.push_back(e);
                }
            }
        }
        return out;
    }

    // Targets with their latest timestamp within [sFrom, sTo], newest first.
    std::vector<std::pair<CString, CString>> Targets(const CIRCNetwork* pNet, const CString& sFrom,
                                                     const CString& sTo) const {
        std::vector<std::pair<CString, CString>> v;
        std::error_code ec;
        fs::path dir = NetDir(pNet);
        if (!fs::is_directory(dir, ec)) return v;
        for (const auto& de : fs::directory_iterator(dir, ec)) {
            std::ifstream l(de.path() / "latest");
            std::ifstream n(de.path() / "name");
            std::string sLatest, sName;
            std::getline(l, sLatest);
            std::getline(n, sName);
            if (sLatest.empty() || sName.empty()) continue;
            if (!sFrom.empty() && sLatest < sFrom) continue;
            if (!sTo.empty() && sLatest > sTo) continue;
            v.emplace_back(sName, sLatest);
        }
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        return v;
    }

    // ---- query handling -------------------------------------------------

    void Fail(CClient* pClient, const CString& sCode, const VCString& vsCtx, const CString& sDesc) {
        PutFail(pClient, kCmd, sCode, vsCtx, sDesc);
    }

    bool ResolveSelector(CClient* pClient, const fs::path& dir, const CString& sSub, const CString& sTarget,
                         const CString& sRaw, Selector& sel, CString& sTime) {
        if (!ParseSelector(sRaw, sel)) {
            Fail(pClient, "INVALID_PARAMS", {sSub, sTarget, sRaw}, "Invalid selector; use timestamp=... or msgid=...");
            return false;
        }
        if (sel.kind == Selector::Time) { sTime = sel.sValue; return true; }
        if (!FindMsgId(dir, sel.sValue, sTime)) {
            Fail(pClient, "MESSAGE_ERROR", {sSub, sTarget, sRaw}, "Unknown message id");
            return false;
        }
        return true;
    }

    void HandleQuery(CClient* pClient, const CMessage& Message) {
        CIRCNetwork* pNet = pClient->GetNetwork();
        const CString sSub = Message.GetParam(0).AsUpper();
        const VCString& vsParams = Message.GetParams();
        if (sSub.empty()) { Fail(pClient, "NEED_MORE_PARAMS", {"*"}, "Missing subcommand"); return; }
        if (!pNet) { Fail(pClient, "INVALID_TARGET", {sSub, "*"}, "Not attached to a network"); return; }
        bool bEvents = m_Caps.Has(pClient, kCapEvents);

        if (sSub == "TARGETS") {
            if (vsParams.size() < 4) { Fail(pClient, "NEED_MORE_PARAMS", {sSub}, "TARGETS <ts> <ts> <limit>"); return; }
            Selector a, b;
            if (!ParseSelector(vsParams[1], a) || a.kind != Selector::Time ||
                !ParseSelector(vsParams[2], b) || b.kind != Selector::Time) {
                Fail(pClient, "INVALID_PARAMS", {sSub, vsParams[1], vsParams[2]}, "TARGETS takes two timestamps");
                return;
            }
            CString sFrom = a.sValue, sTo = b.sValue;
            if (sFrom > sTo) std::swap(sFrom, sTo);
            size_t uLimit = Limit(vsParams[3]);
            auto v = Targets(pNet, sFrom, sTo);
            if (v.size() > uLimit) v.resize(uLimit);
            bool bBatch = pClient->HasBatch();
            CString sRef = "ch" + ircv3::RandomId(8);
            if (bBatch) pClient->PutClient(":irc.znc.in BATCH +" + sRef + " draft/chathistory-targets");
            for (const auto& kv : v) {
                CString sLine = ":irc.znc.in CHATHISTORY TARGETS " + kv.first + " " + kv.second;
                if (bBatch) sLine = "@batch=" + sRef + " " + sLine;
                pClient->PutClient(sLine);
            }
            if (bBatch) pClient->PutClient(":irc.znc.in BATCH -" + sRef);
            return;
        }

        if (sSub != "LATEST" && sSub != "BEFORE" && sSub != "AFTER" && sSub != "AROUND" && sSub != "BETWEEN") {
            Fail(pClient, "INVALID_PARAMS", {sSub}, "Unknown subcommand");
            return;
        }
        size_t uNeeded = sSub == "BETWEEN" ? 5 : 4;
        if (vsParams.size() < uNeeded) {
            Fail(pClient, "NEED_MORE_PARAMS", {sSub}, sSub + " <target> <selector> " +
                                                          (sSub == "BETWEEN" ? "<selector> " : "") + "<limit>");
            return;
        }
        const CString& sTarget = vsParams[1];
        if (sTarget.empty() || sTarget.find_first_of(" ,") != CString::npos) {
            Fail(pClient, "INVALID_TARGET", {sSub, sTarget}, "Invalid target");
            return;
        }
        // Canonical name: the channel as ZNC knows it, else as given.
        CString sCanon = sTarget;
        if (CChan* pChan = pNet->FindChan(sTarget)) sCanon = pChan->GetName();
        fs::path dir = TargetDir(pNet, sTarget);
        size_t uLimit = Limit(vsParams.back());
        std::vector<Entry> result;
        Selector s1, s2;
        CString t1, t2;

        if (sSub == "LATEST") {
            if (vsParams[2] != "*") {
                if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[2], s1, t1)) return;
            }
            result = Query(dir, t1, "", uLimit, true, bEvents, s1.kind == Selector::MsgId ? s1.sValue : "");
        } else if (sSub == "BEFORE") {
            if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[2], s1, t1)) return;
            // Exclusive of the selector: for msgid, allow equal timestamps but
            // not the message itself.
            result = Query(dir, "", s1.kind == Selector::Time ? t1 : NextMs(t1), uLimit, true, bEvents,
                           s1.kind == Selector::MsgId ? s1.sValue : "");
        } else if (sSub == "AFTER") {
            if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[2], s1, t1)) return;
            result = Query(dir, s1.kind == Selector::Time ? t1 : PrevMs(t1), "", uLimit, false, bEvents,
                           s1.kind == Selector::MsgId ? s1.sValue : "");
        } else if (sSub == "AROUND") {
            if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[2], s1, t1)) return;
            size_t uHalf = uLimit / 2;
            std::vector<Entry> before = Query(dir, "", t1, uHalf, true, bEvents);
            std::vector<Entry> after = Query(dir, PrevMs(t1), "", uLimit - before.size(), false, bEvents);
            result = before;
            result.insert(result.end(), after.begin(), after.end());
        } else {  // BETWEEN
            if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[2], s1, t1)) return;
            if (!ResolveSelector(pClient, dir, sSub, sTarget, vsParams[3], s2, t2)) return;
            bool bBackwards = t1 > t2;
            CString sLo = bBackwards ? t2 : t1, sHi = bBackwards ? t1 : t2;
            result = Query(dir, sLo, sHi, uLimit, bBackwards, bEvents);
            // exclude both endpoints when they were msgids with equal timestamps
            CString ex1 = s1.kind == Selector::MsgId ? s1.sValue : "", ex2 = s2.kind == Selector::MsgId ? s2.sValue : "";
            if (!ex1.empty() || !ex2.empty())
                result.erase(std::remove_if(result.begin(), result.end(),
                                            [&](const Entry& e) { return e.sMsgId == ex1 || e.sMsgId == ex2; }),
                             result.end());
        }
        SendBatch(pClient, sCanon, result, result.size() < uLimit);
    }

    size_t Limit(const CString& s) const {
        unsigned long u = s.ToULong();
        if (u == 0 || u > m_uLimit) return m_uLimit;
        return u;
    }

    // Timestamps one millisecond off, to turn inclusive bounds into the
    // exclusive ones Query() uses.
    static CString NextMs(const CString& s) { return ShiftMs(s, 1); }
    static CString PrevMs(const CString& s) { return ShiftMs(s, -1); }
    static CString ShiftMs(const CString& s, int d) {
        struct tm tm = {};
        int ms = 0;
        if (sscanf(s.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour,
                   &tm.tm_min, &tm.tm_sec, &ms) != 7)
            return s;
        tm.tm_year -= 1900;
        tm.tm_mon -= 1;
        time_t t = timegm(&tm);
        long long total = (long long)t * 1000 + ms + d;
        time_t t2 = total / 1000;
        int ms2 = (int)(total % 1000);
        struct tm out;
        gmtime_r(&t2, &out);
        char buf[64];
        snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", out.tm_year + 1900, out.tm_mon + 1,
                 out.tm_mday, out.tm_hour, out.tm_min, out.tm_sec, ms2);
        return buf;
    }

    // ---- SEARCH (soju.im/search) ----------------------------------------

    void HandleSearch(CClient* pClient, const CMessage& Message) {
        auto fail = [&](const CString& sCode, const CString& sAttr, const CString& sDesc) {
            PutFail(pClient, kSearchCmd, sCode, {sAttr}, sDesc);
        };
        CIRCNetwork* pNet = pClient->GetNetwork();
        if (!pNet) { fail("INVALID_PARAMS", "in", "Not bound to a network"); return; }
        if (!m_Caps.Has(pClient, kCapSearch)) { fail("INVALID_PARAMS", "*", CString(kCapSearch) + " was not negotiated"); return; }
        // One parameter, with spaces escaped as \s like message tags; be
        // lenient with clients that send them unescaped (several params).
        CString sAttrs;
        for (const CString& sParam : Message.GetParams()) sAttrs += (sAttrs.empty() ? "" : " ") + sParam;
        if (sAttrs.empty()) { fail("INVALID_PARAMS", "*", "Missing attributes"); return; }
        MCString attrs = ircv3::DecodeAttrs(sAttrs);
        static const std::set<CString> ssKnown = {"in", "from", "after", "before", "text", "limit"};
        for (const auto& kv : attrs)
            if (!ssKnown.count(kv.first)) { fail("INVALID_PARAMS", kv.first, "Unknown attribute"); return; }
        if (!attrs.count("in") && !attrs.count("from") && !attrs.count("text")) {
            fail("INVALID_PARAMS", "*", "Give at least one of in, from, text");
            return;
        }
        CString sIn = attrs["in"], sFrom = attrs["from"], sText = attrs["text"].AsLower();
        CString sAfter = attrs["after"], sBefore = attrs["before"];
        if (!sAfter.empty() && !IsTimestamp(sAfter)) { fail("INVALID_PARAMS", "after", "Expected YYYY-MM-DDThh:mm:ss.sssZ"); return; }
        if (!sBefore.empty() && !IsTimestamp(sBefore)) { fail("INVALID_PARAMS", "before", "Expected YYYY-MM-DDThh:mm:ss.sssZ"); return; }
        if (sBefore.empty()) sBefore = CUtils::FormatServerTime(CUtils::GetTime());
        size_t uLimit = m_uLimit;
        if (attrs.count("limit")) {
            const CString& l = attrs["limit"];
            if (l.empty() || l.find_first_not_of("0123456789") != CString::npos || l.ToULong() == 0) {
                fail("INVALID_PARAMS", "limit", "Expected a positive number");
                return;
            }
            uLimit = std::min<size_t>(l.ToULong(), m_uLimit);
        }
        const bool bForward = !sAfter.empty();

        const CString sNetDir = SafeName(pNet->GetName());
        const CString sTextPlain = ircv3::StripFormatting(sText);
        bool bTruncated = false;
        std::vector<Entry> found;
        std::set<CString> ssSeen;
        auto remember = [&](const Entry& e) { return ssSeen.insert(e.sMsgId.empty() ? e.sLine : e.sMsgId).second; };

        // 1. The index.
        SearchIndex* pIdx = IndexFor(pNet->GetUser());
        if (pIdx) {
            ircv3::SearchSpec spec;
            spec.sNetwork = sNetDir;
            if (!sIn.empty()) spec.sTarget = SafeName(sIn);
            spec.sNick = sFrom.AsLower();
            spec.sAfter = sAfter;
            spec.sBefore = sBefore;
            spec.sText = sTextPlain;
            spec.uLimit = uLimit;
            spec.bForward = bForward;
            spec.lMaxMillis = m_lSearchMaxMillis;
            std::vector<ircv3::IndexHit> hits;
            bool bCut = false;
            if (pIdx->Search(spec, hits, bCut)) {
                bTruncated |= bCut;
                std::map<CString, std::vector<Entry>> mDays;  // day files re-read after a rewrite
                bool bStale = false;
                for (const ircv3::IndexHit& h : hits) {
                    fs::path dir = NetDir(pNet) / h.sTarget.c_str();
                    CString sLine = ReadLineAt(DayPath(dir, h.sDay), h.lOff, h.lLen);
                    Entry e;
                    if (!sLine.empty()) e = ParseEntry(sLine);
                    if (sLine.empty() || (!h.sMsgId.empty() && e.sMsgId != h.sMsgId)) {
                        // The file was rewritten (importer, redaction) since
                        // it was indexed: find the message by id instead.
                        bStale = true;
                        const CString sKey = h.sTarget + "/" + h.sDay;
                        if (!mDays.count(sKey)) mDays[sKey] = ReadDay(dir, h.sDay);
                        const std::vector<Entry>& day = mDays[sKey];
                        auto f = std::find_if(day.begin(), day.end(), [&](const Entry& x) { return x.sMsgId == h.sMsgId; });
                        if (h.sMsgId.empty() || f == day.end()) continue;
                        e = *f;
                    }
                    if (remember(e)) found.push_back(std::move(e));
                }
                if (bStale) StartSync(false);
            } else {
                DEBUG("chathistory: index search failed: " << pIdx->LastError());
                bTruncated = true;
            }
        }

        // 2. Day files the index does not cover: none once a sync has run,
        // otherwise those whose size differs from the indexed size. Scanned
        // newest first within the budget, newest (or oldest) uLimit per
        // target since only those can make the final cut.
        if (!pIdx || !m_bIndexReady) {
            std::map<CString, long long> sizes;
            if (pIdx) sizes = pIdx->DaySizes(sNetDir);
            std::vector<fs::path> dirs;
            std::error_code ec;
            if (!sIn.empty()) {
                fs::path d = TargetDir(pNet, sIn);
                if (fs::is_directory(d, ec)) dirs.push_back(d);
            } else {
                fs::path nd = NetDir(pNet);
                if (fs::is_directory(nd, ec))
                    for (const auto& de : fs::directory_iterator(nd, ec))
                        if (fs::is_directory(de.path(), ec)) dirs.push_back(de.path());
            }
            auto indexed = [&](const fs::path& dir, const CString& sDay) {
                if (!pIdx) return false;
                auto it = sizes.find(SearchIndex::DayKey(sNetDir, dir.filename().string(), sDay));
                if (it == sizes.end()) return false;
                std::error_code e2;
                return (long long)fs::file_size(DayPath(dir, sDay), e2) == it->second && !e2;
            };
            const auto tStart = std::chrono::steady_clock::now();
            size_t uScanned = 0;
            bool bOverBudget = false;
            auto budget = [&]() {
                if (bOverBudget) return false;
                if (uScanned > m_uSearchMaxLines ||
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tStart).count() >
                        m_lSearchMaxMillis) {
                    bOverBudget = true;
                    return false;
                }
                return true;
            };
            auto consider = [&](const CString& sRaw, std::vector<Entry>& out) {
                uScanned++;
                if (!sTextPlain.empty() && ircv3::StripFormatting(sRaw).AsLower().find(sTextPlain.AsLower()) == CString::npos) return;
                Entry e = ParseEntry(sRaw);
                if (e.bEvent) return;
                if (!sAfter.empty() && e.sTime < sAfter) return;
                if (e.sTime > sBefore) return;
                CMessage m(sRaw);
                const CString& sCmd = m.GetCommand();
                if (!sCmd.Equals("PRIVMSG") && !sCmd.Equals("NOTICE")) return;
                if (!sFrom.empty() && !m.GetNick().NickEquals(sFrom)) return;
                if (!sTextPlain.empty() &&
                    ircv3::StripFormatting(m.GetParam(1)).AsLower().find(sTextPlain.AsLower()) == CString::npos)
                    return;
                if (remember(e)) out.push_back(std::move(e));
            };
            for (const fs::path& dir : dirs) {
                if (!budget()) break;
                std::vector<CString> days = DayFiles(dir);
                std::vector<Entry> mine;
                if (bForward) {
                    for (auto it = days.begin(); it != days.end() && mine.size() < uLimit && budget(); ++it) {
                        if (*it < sAfter.substr(0, 10) || *it > sBefore.substr(0, 10) || indexed(dir, *it)) continue;
                        for (const Entry& e : ReadDay(dir, *it)) {
                            if (mine.size() >= uLimit || !budget()) break;
                            consider(e.sLine, mine);
                        }
                    }
                } else {
                    for (auto it = days.rbegin(); it != days.rend() && mine.size() < uLimit && budget(); ++it) {
                        if (*it > sBefore.substr(0, 10) || indexed(dir, *it)) continue;
                        std::vector<Entry> day = ReadDay(dir, *it);  // sorted
                        for (auto e = day.rbegin(); e != day.rend() && mine.size() < uLimit && budget(); ++e)
                            consider(e->sLine, mine);
                    }
                }
                found.insert(found.end(), mine.begin(), mine.end());
            }
            if (bOverBudget) {
                bTruncated = true;
                DEBUG("chathistory: search for " << pNet->GetUser()->GetUsername() << " hit the scan budget after " << uScanned << " lines");
            }
        }

        std::stable_sort(found.begin(), found.end(), [](const Entry& a, const Entry& b) {
            return a.sTime != b.sTime ? a.sTime < b.sTime : a.sMsgId < b.sMsgId;
        });
        if (found.size() > uLimit) {
            if (bForward) found.resize(uLimit);
            else found.erase(found.begin(), found.end() - uLimit);
        }

        if (bTruncated && m_Caps.HasOrCore(pClient, kStandardReplies))
            PutNote(pClient, kSearchCmd, "TRUNCATED", {}, "Results may be incomplete");
        bool bBatch = pClient->HasBatch();
        CString sRef = "se" + ircv3::RandomId(8);
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH +" + sRef + " " + kSearchBatch);
        for (const Entry& e : found) {
            CMessage m(e.sLine);
            m.GetTags().erase(kEventTag);
            if (bBatch) m.SetTag("batch", sRef);
            pClient->PutClient(m.ToString());
        }
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH -" + sRef);
    }

    void SendBatch(CClient* pClient, const CString& sTarget, const std::vector<Entry>& v, bool bEnd) {
        bool bBatch = pClient->HasBatch();
        CString sRef = "ch" + ircv3::RandomId(8);
        if (bBatch) {
            CString sOpen = ":irc.znc.in BATCH +" + sRef + " chathistory " + sTarget;
            if (bEnd) sOpen = "@draft/chathistory-end " + sOpen;
            pClient->PutClient(sOpen);
        }
        for (const Entry& e : v) {
            CMessage m(e.sLine);
            m.GetTags().erase(kEventTag);
            if (bBatch) m.SetTag("batch", sRef);
            pClient->PutClient(m.ToString());
        }
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH -" + sRef);
    }

    MCString ISupportFor(CClient* pClient) {
        if (!pClient || !m_Caps.Has(pClient, kCap)) return {};
        return {{"CHATHISTORY", CString(m_uLimit)}, {"MSGREFTYPES", "timestamp,msgid"}};
    }

    // ---- retention ------------------------------------------------------

    static void PruneTimer(CModule* pModule, CFPTimer* pTimer) {
        auto* pMod = static_cast<CChatHistory*>(pModule);
        pMod->Prune();
        pMod->StartSync(false);
    }

    void Prune() {
        if (m_uDays == 0) return;
        time_t cutoff = time(nullptr) - (time_t)m_uDays * 86400;
        struct tm tm;
        gmtime_r(&cutoff, &tm);
        char buf[64];
        snprintf(buf, sizeof buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
        const CString sCutoff = buf;
        std::error_code ec;
        fs::path root(GetSavePath().c_str());
        if (!fs::is_directory(root, ec)) return;
        for (const auto& user : fs::directory_iterator(root, ec)) {
            const CString sUserDir = user.path().filename().string();
            if (sUserDir.StartsWith(".") || !fs::is_directory(user.path(), ec)) continue;
            for (const auto& net : fs::directory_iterator(user.path(), ec))
                for (const auto& target : fs::directory_iterator(net.path(), ec))
                    for (const CString& day : DayFiles(target.path())) {
                        if (day >= sCutoff) continue;
                        if (!fs::remove(DayPath(target.path(), day), ec)) continue;
                        if (SearchIndex* pIdx = IndexForDir(sUserDir))
                            pIdx->DeleteDay(net.path().filename().string(), target.path().filename().string(), day);
                    }
        }
    }

    CapTracker m_Caps;
    ircv3::ClientMap<bool> m_mSearchWithdrawn;  // soju.im/search CAP DEL'd on an unbound connection
    ircv3::ClientMap<bool> m_mLoggedIn;
    ircv3::ISupportBurst m_Burst{{"CHATHISTORY", "MSGREFTYPES"}};
    unsigned m_uDays = 90;
    unsigned m_uLimit = 1000;
    size_t m_uSearchMaxLines = kSearchMaxLines;
    long m_lSearchMaxMillis = kSearchMaxMillis;
    std::map<CString, std::unique_ptr<SearchIndex>> m_mIndexes;  // user dir -> index (null = failed)
    std::map<CString, CString> m_mIndexErrors;
    std::map<CString, time_t> m_mIndexRetry;
    bool m_bSyncing = false, m_bSyncPending = false, m_bSyncPendingFull = false;
    bool m_bIndexReady = false;  // a sync finished: every day file on disk is in the index
    CString m_sSyncReport;
};

void CSyncJob::runMain() { static_cast<CChatHistory*>(GetModule())->OnSyncDone(*this); }

template <>
void TModInfo<CChatHistory>(CModInfo& Info) {
    Info.SetWikiPage("chathistory");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("days=<retention days, default 90> limit=<max messages per request, default 1000> "
                         "searchlines=<scan budget, default 400000> searchms=<search budget ms, default 2000>");
}

GLOBALMODULEDEFS(CChatHistory, "draft/chathistory: persistent message history clients can page through")
