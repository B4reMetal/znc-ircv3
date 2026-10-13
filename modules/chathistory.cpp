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
 *            first in a soju.im/search batch; bounded by a line and time
 *            budget; the cap is withdrawn on unbound connections)
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

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <vector>

namespace fs = std::filesystem;
using ircv3::CapTracker;
using ircv3::PutFail;

namespace {
const char* kCap = "draft/chathistory";
const char* kCapEvents = "draft/event-playback";
const char* kCapRedact = "draft/message-redaction";
const char* kEventTag = "znc.in/event";
const char* kCmd = "CHATHISTORY";
const char* kCapSearch = "soju.im/search";
const char* kSearchCmd = "SEARCH";
const char* kSearchBatch = "soju.im/search";
// Per-query budget: a broad pattern over a large store must not stall ZNC.
const size_t kSearchMaxLines = 400000;
const long kSearchMaxMillis = 2000;

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
}  // namespace

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
            else { sMessage = "Unknown argument " + s + " (use days=N limit=N)"; return false; }
        }
        if (m_uLimit == 0) m_uLimit = 1000;
        std::error_code ec;
        fs::create_directories(GetSavePath().c_str(), ec);
        Prune();
        AddTimer(PruneTimer, "prune", 3600, 0, "Prune old history");
        return true;
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
        if (IsOurCap(sCap)) m_Caps.Set(pClient, sCap, bState);
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
        } else {
            PutModule("Commands: status, prune");
        }
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
        std::ofstream f(dir / (sDay.c_str() + CString(".log")).c_str(), std::ios::app);
        f << sLine << "\n";
        std::ofstream l(dir / "latest", std::ios::trunc);
        l << tags["time"] << "\n";
        std::ofstream n(dir / "name", std::ios::trunc);
        n << sTarget << "\n";
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
            std::ofstream f(dir / (it->c_str() + CString(".log")).c_str(), std::ios::trunc);
            for (const Entry& e : v) f << e.sLine << "\n";
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

    std::vector<CString> DayFiles(const fs::path& dir) const {
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

        // Which stores to scan.
        std::vector<fs::path> dirs;
        std::error_code ec;
        if (!sIn.empty()) {
            fs::path d = TargetDir(pNet, sIn);
            if (fs::is_directory(d, ec)) dirs.push_back(d);
        } else {
            fs::path nd = NetDir(pNet);
            if (fs::is_directory(nd, ec))
                for (const auto& de : fs::directory_iterator(nd, ec)) dirs.push_back(de.path());
        }

        // Scan within the budget. Per target only the newest (or oldest)
        // uLimit matches can make the final cut, so stop there.
        const auto tStart = std::chrono::steady_clock::now();
        size_t uScanned = 0;
        bool bOverBudget = false;
        auto budget = [&]() {
            if (bOverBudget) return false;
            if (uScanned > kSearchMaxLines ||
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - tStart).count() > kSearchMaxMillis) {
                bOverBudget = true;
                return false;
            }
            return true;
        };
        std::vector<Entry> found;
        auto consider = [&](const std::string& sRaw, std::vector<Entry>& out) {
            uScanned++;
            if (!sText.empty() && CString(sRaw).AsLower().find(sText) == CString::npos) return;
            Entry e = ParseEntry(sRaw);
            if (e.bEvent) return;
            if (!sAfter.empty() && e.sTime < sAfter) return;
            if (e.sTime > sBefore) return;
            CMessage m(sRaw);
            const CString& sCmd = m.GetCommand();
            if (!sCmd.Equals("PRIVMSG") && !sCmd.Equals("NOTICE")) return;
            if (!sFrom.empty() && !m.GetNick().NickEquals(sFrom)) return;
            if (!sText.empty() && m.GetParam(1).AsLower().find(sText) == CString::npos) return;
            out.push_back(std::move(e));
        };
        for (const fs::path& dir : dirs) {
            if (!budget()) break;
            std::vector<CString> days = DayFiles(dir);
            std::vector<Entry> mine;
            if (bForward) {
                for (auto it = days.begin(); it != days.end() && mine.size() < uLimit && budget(); ++it) {
                    if (*it < sAfter.substr(0, 10) || *it > sBefore.substr(0, 10)) continue;
                    for (const Entry& e : ReadDay(dir, *it)) {
                        if (mine.size() >= uLimit || !budget()) break;
                        consider(e.sLine, mine);
                    }
                }
            } else {
                for (auto it = days.rbegin(); it != days.rend() && mine.size() < uLimit && budget(); ++it) {
                    if (*it > sBefore.substr(0, 10)) continue;
                    std::vector<Entry> day = ReadDay(dir, *it);  // sorted
                    for (auto e = day.rbegin(); e != day.rend() && mine.size() < uLimit && budget(); ++e)
                        consider(e->sLine, mine);
                }
            }
            found.insert(found.end(), mine.begin(), mine.end());
        }
        std::stable_sort(found.begin(), found.end(), [](const Entry& a, const Entry& b) { return a.sTime < b.sTime; });
        if (found.size() > uLimit) {
            if (bForward) found.resize(uLimit);
            else found.erase(found.begin(), found.end() - uLimit);
        }
        if (bOverBudget) DEBUG("chathistory: search for " << pNet->GetUser()->GetUsername() << " hit the budget after " << uScanned << " lines");

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

    static void PruneTimer(CModule* pModule, CFPTimer* pTimer) { static_cast<CChatHistory*>(pModule)->Prune(); }

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
        for (const auto& user : fs::directory_iterator(root, ec))
            for (const auto& net : fs::directory_iterator(user.path(), ec))
                for (const auto& target : fs::directory_iterator(net.path(), ec))
                    for (const CString& day : DayFiles(target.path()))
                        if (day < sCutoff) fs::remove(target.path() / (day.c_str() + CString(".log")).c_str(), ec);
    }

    CapTracker m_Caps;
    ircv3::ClientMap<bool> m_mSearchWithdrawn;  // soju.im/search CAP DEL'd on an unbound connection
    ircv3::ClientMap<bool> m_mLoggedIn;
    ircv3::ISupportBurst m_Burst{{"CHATHISTORY", "MSGREFTYPES"}};
    unsigned m_uDays = 90;
    unsigned m_uLimit = 1000;
};

template <>
void TModInfo<CChatHistory>(CModInfo& Info) {
    Info.SetWikiPage("chathistory");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("days=<retention days, default 90> limit=<max messages per request, default 1000>");
}

GLOBALMODULEDEFS(CChatHistory, "draft/chathistory: persistent message history clients can page through")
