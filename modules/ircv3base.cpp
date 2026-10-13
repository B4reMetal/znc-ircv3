/*
 * ircv3base — foundation capabilities for the znc-ircv3 module set.
 *
 * Global module. Provides, for every user and network:
 *   - standard-replies: offered to clients, requested from servers; upstream
 *     FAIL/WARN/NOTE lines are only delivered to clients that negotiated the
 *     cap, except for commands whose own spec defines them (BOUNCER,
 *     CHATHISTORY, MARKREAD, READ, SETNAME, REDACT, BATCH).
 *   - msgid minting: messages that reach a buffer without a msgid tag get a
 *     ZNC-namespaced one ("znc-<net>-<counter>"), so chathistory and
 *     labeled-response can reference them even when the upstream server
 *     does not implement message-ids. ZNC-minted ids never go upstream.
 *   - server-side batch: requests the batch cap from servers; BATCH lines
 *     and the batch tag are only forwarded to clients that have the cap.
 *   - setname: requested from servers, offered to clients; upstream SETNAME
 *     updates the network's realname and reaches only capable clients;
 *     client SETNAME fails cleanly when the upstream lacks the cap.
 *   - draft/pre-away: AWAY sent before registration is applied at login.
 *     Every client's away state (pre-away or AWAY) is recorded on the
 *     CClient, so other modules (webpush) can tell present clients from
 *     absent ones.
 *   - no-implicit-names (+ draft/): NAMES replies reach capable clients only
 *     when they asked for them.
 *   - extended-monitor (+ draft/): server dependent (core API, so it is
 *     listed/announced only once the server has ACKed it). MONITOR lists are
 *     tracked per network and AWAY/ACCOUNT/CHGHOST/SETNAME from monitored
 *     nicks that share no attached channel are forwarded to clients that
 *     enabled the cap; the core would drop them (or, for SETNAME, send
 *     them to everyone).
 *   - attach replay: the JOINs ZNC replays when a client attaches carry
 *     the time of the real join instead of the attach time.
 *   - echo-message upstream: ZNC's core echoes a client's message itself,
 *     with its own clock and a ZNC msgid, and never asks the server for
 *     echo-message. When the server offers it, this module requests it,
 *     forwards the client's message without the core's echo and buffer
 *     entry, and when the server's echo comes back feeds it through the
 *     sending client's input path, so buffers, chathistory and every
 *     client get the message with the server's msgid and time, with the
 *     usual echo-message / znc.in/self-message delivery rules.
 */
#include <znc/Modules.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/User.h>
#include <znc/znc.h>

#include <znc/Chan.h>
#include <znc/Query.h>
#include <znc/Utils.h>

#include "caps.h"
#include "clients.h"
#include "replies.h"

#include <algorithm>
#include <memory>
#include <ctime>
#include <map>
#include <set>

using ircv3::CapTracker;

namespace {

const char* kStandardReplies = "standard-replies";
const char* kBatch = "batch";
const char* kSetName = "setname";
const char* kPreAway = "draft/pre-away";
const char* kNoNames = "no-implicit-names";
const char* kNoNamesDraft = "draft/no-implicit-names";
const char* kEchoMessage = "echo-message";
const char* kExtMon = "extended-monitor";
const char* kExtMonDraft = "draft/extended-monitor";

bool ServerHas(CIRCNetwork* pNet, const CString& sCap) {
    CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
    return pSock && pSock->IsCapAccepted(sCap);
}

// Commands whose specs define FAIL/WARN/NOTE replies; those may be sent to
// clients regardless of the standard-replies cap.
const std::set<CString> kCommandsWithOwnReplies = {
    "BOUNCER", "CHATHISTORY", "MARKREAD", "READ", "SETNAME",
    "REDACT", "BATCH", "WEBPUSH", "REGISTER", "VERIFY", "MONITOR", "SEARCH"};

bool IsStandardReply(const CString& sCmd) {
    return sCmd.Equals("FAIL") || sCmd.Equals("WARN") || sCmd.Equals("NOTE");
}

}  // namespace

class CIrcv3Base : public CModule {
  public:
    MODCONSTRUCTOR(CIrcv3Base) {
        AddServerDependentCapability(kExtMon, std::make_unique<ExtMonCap>());
        AddServerDependentCapability(kExtMonDraft, std::make_unique<ExtMonCap>());
    }

    struct PendingEcho {
        CClient* pClient;
        uint64_t uStart;  // socket start time, to recognise a reused address
        CString sKey;
        time_t tSent;
    };

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "ircv3base must be loaded as a global module";
            return false;
        }
        return true;
    }

    // ---- client capabilities -------------------------------------------

    static bool IsOurCap(const CString& sCap) {
        return sCap.Equals(kStandardReplies) || sCap.Equals(kSetName) || sCap.Equals(kPreAway) ||
               sCap.Equals(kNoNames) || sCap.Equals(kNoNamesDraft);
    }

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(kStandardReplies);
        ssCaps.insert(kSetName);
        ssCaps.insert(kPreAway);
        ssCaps.insert(kNoNames);
        ssCaps.insert(kNoNamesDraft);
    }

    bool IsClientCapSupported(CClient* pClient, const CString& sCap,
                              bool bState) override {
        return IsOurCap(sCap);
    }

    void OnClientCapRequest(CClient* pClient, const CString& sCap,
                            bool bState) override {
        if (IsOurCap(sCap)) m_Caps.Set(pClient, sCap, bState);
    }

    void OnClientDisconnect() override {
        m_Caps.Forget(GetClient());
        m_mPreAway.Erase(GetClient());
        m_mNamesWanted.Erase(GetClient());
        for (auto& kv : m_mPending)
            for (auto it = kv.second.begin(); it != kv.second.end();)
                it = it->pClient == GetClient() ? kv.second.erase(it) : std::next(it);
    }

    // ---- extended-monitor --------------------------------------------
    // Registered through AddServerDependentCapability (in the constructor),
    // so the core lists it in CAP LS / sends CAP NEW only while the server
    // has it. The flag is kept in m_Caps under the ratified name.

    class ExtMonCap : public CCapability {
      public:
        void OnClientChangedSupport(CClient* pClient, bool bState) override {
            static_cast<CIrcv3Base*>(GetModule())->m_Caps.Set(pClient, kExtMon, bState);
        }
    };

    bool ServerHasExtMon(CIRCNetwork* pNet) const { return ServerHas(pNet, kExtMon) || ServerHas(pNet, kExtMonDraft); }

    static bool VisibleInAttachedChannels(CIRCNetwork* pNet, const CString& sNick) {
        for (const CChan* pChan : pNet->GetChans())
            if (!pChan->IsDetached() && pChan->FindNick(sNick)) return true;
        return false;
    }

    // MONITOR + / - / C from any client, and 730/731/732 from the server.
    void TrackMonitor(CIRCNetwork* pNet, char cOp, const CString& sTargets) {
        std::set<CString>& ss = m_mMonitored[pNet];
        if (cOp == 'C') { ss.clear(); return; }
        VCString vs;
        sTargets.Split(",", vs, false);
        for (CString& s : vs) {
            s = s.Token(0, false, "!").AsLower();
            if (s.empty()) continue;
            if (cOp == '-') ss.erase(s); else ss.insert(s);
        }
    }

    bool IsMonitored(CIRCNetwork* pNet, const CString& sNick) const {
        auto it = m_mMonitored.find(pNet);
        return it != m_mMonitored.end() && it->second.count(sNick.AsLower());
    }

    // AWAY / ACCOUNT / CHGHOST / SETNAME from a nick we share no attached
    // channel with. Returns HALT when the message must not reach the core
    // (SETNAME, which it would broadcast), CONTINUE otherwise (the core
    // drops the others itself for such nicks).
    EModRet MonitoredChange(CMessage& Message, CIRCNetwork* pNet) {
        const CString& sCmd = Message.GetCommand();
        const CString sNick = Message.GetNick().GetNick();
        if (sNick.empty() || VisibleInAttachedChannels(pNet, sNick)) return CONTINUE;
        const EModRet eHidden = sCmd.Equals("SETNAME") ? HALT : CONTINUE;
        if (!ServerHasExtMon(pNet) || !IsMonitored(pNet, sNick)) return eHidden;
        for (CClient* pClient : pNet->GetClients()) {
            if (!m_Caps.Has(pClient, kExtMon)) continue;
            if (sCmd.Equals("CHGHOST") && !pClient->HasChgHost()) continue;
            if (sCmd.Equals("SETNAME") && !m_Caps.Has(pClient, kSetName)) continue;
            pClient->PutClient(Message);  // AWAY / ACCOUNT are gated on their caps inside
        }
        return eHidden;
    }

    void OnIRCDisconnected() override { m_mMonitored.erase(GetNetwork()); }

    bool NoImplicitNames(const CClient* pClient) const {
        return m_Caps.Has(pClient, kNoNames) || m_Caps.Has(pClient, kNoNamesDraft);
    }

    // ---- pre-away ------------------------------------------------------

    EModRet OnUnknownUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient();
        if (!pClient || !Message.GetCommand().Equals("AWAY")) return CONTINUE;
        if (!m_Caps.Has(pClient, kPreAway)) return CONTINUE;
        // "AWAY *" keeps whatever state the network has; otherwise remember
        // the reason ("" = back) and apply it once attached.
        CString sReason = Message.GetParam(0);
        if (sReason != "*") {
            m_mPreAway[pClient] = sReason;
            pClient->SetAway(!sReason.empty());
        }
        return HALT;
    }

    void OnClientLogin() override {
        CClient* pClient = GetClient();
        CString* pReason = m_mPreAway.Find(pClient);
        if (!pReason) return;
        if (pClient->GetNetwork()) {
            if (pReason->empty())
                pClient->PutIRC("AWAY");
            else
                pClient->PutIRC("AWAY :" + *pReason);
        }
        m_mPreAway.Erase(pClient);
    }

    // ---- client commands: SETNAME, NAMES -------------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return CONTINUE;
        const CString& sCmd = Message.GetCommand();
        if (sCmd.Equals("AWAY")) {
            // ZNC's core forwards AWAY but does not record it per client.
            pClient->SetAway(!Message.GetParam(0).empty());
            return CONTINUE;
        }
        if (sCmd.Equals("SETNAME")) {
            CIRCNetwork* pNet = pClient->GetNetwork();
            CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
            if (!pSock || !pSock->IsCapAccepted(kSetName)) {
                ircv3::PutFail(pClient, "SETNAME", "CANNOT_CHANGE_REALNAME", {},
                               "The server does not support changing the realname");
                return HALT;
            }
            return CONTINUE;  // forwarded; the server echoes SETNAME back
        }
        if (sCmd.Equals("MONITOR") && pClient->GetNetwork()) {
            const CString sOp = Message.GetParam(0).AsUpper();
            if (sOp == "+" || sOp == "-" || sOp == "C") TrackMonitor(pClient->GetNetwork(), sOp[0], Message.GetParam(1));
            return CONTINUE;
        }
        if (sCmd.Equals("NAMES") && NoImplicitNames(pClient)) {
            VCString vs;
            Message.GetParam(0).Split(",", vs, false);
            std::set<CString>& ss = m_mNamesWanted[pClient];
            for (const CString& s : vs) ss.insert(s.AsLower());
            if (vs.empty()) ss.insert("*");
        }
        return CONTINUE;
    }

    // ---- upstream SETNAME, server echoes --------------------------------

    EModRet OnRawMessage(CMessage& Message) override {
        const CString& sCmd = Message.GetCommand();
        CIRCNetwork* pNet = Message.GetNetwork() ? Message.GetNetwork() : GetNetwork();
        if (!pNet) return CONTINUE;
        if (sCmd == "730" || sCmd == "731" || sCmd == "732") {
            TrackMonitor(pNet, '+', Message.GetParam(1));  // RPL_MONONLINE/OFFLINE/LIST
            return CONTINUE;
        }
        if (!Message.GetNick().NickEquals(pNet->GetCurNick())) {
            if (sCmd.Equals("AWAY") || sCmd.Equals("ACCOUNT") || sCmd.Equals("CHGHOST") || sCmd.Equals("SETNAME"))
                return MonitoredChange(Message, pNet);
            return CONTINUE;
        }
        if (sCmd.Equals("SETNAME")) {
            pNet->SetRealName(Message.GetParam(0));
            return CONTINUE;  // broadcast by the core, filtered per client below
        }
        if (sCmd.Equals("PRIVMSG") || sCmd.Equals("NOTICE") || sCmd.Equals("TAGMSG")) return ServerEcho(Message, pNet);
        if (sCmd.Equals("BATCH") && Message.GetParam(0).StartsWith("+") && Message.GetParam(1).Equals("draft/multiline") &&
            UpstreamEcho(pNet)) {
            // The echo of a client's multiline batch. The core forwards the
            // framing itself; remember whose it is so the sender only gets
            // it with echo-message (the inner lines go through ServerEcho).
            auto pv = m_mPending.find(pNet);
            if (pv != m_mPending.end()) {
                const CString sPrefix = Message.GetParam(2).AsLower() + " ";
                for (const PendingEcho& e : pv->second) {
                    if (!e.sKey.StartsWith(sPrefix)) continue;
                    m_mEchoBatches[Message.GetParam(0).substr(1)] = {e.pClient, e.uStart, "", time(nullptr)};
                    break;
                }
            }
        }
        return CONTINUE;
    }

    // ---- server capabilities -------------------------------------------

    bool OnServerCap302Available(const CString& sCap,
                                 const CString& sValue) override {
        return sCap.Equals(kStandardReplies) || sCap.Equals(kBatch) || sCap.Equals(kSetName) ||
               sCap.Equals(kEchoMessage);
    }

    // ---- outgoing filtering --------------------------------------------

    EModRet OnSendToClientMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return CONTINUE;

        const CString& sCmd = Message.GetCommand();
        if (IsStandardReply(sCmd)) {
            if (m_Caps.HasOrCore(pClient, kStandardReplies)) return CONTINUE;
            // FAIL <command> <code> ...: the first param is the command.
            if (kCommandsWithOwnReplies.count(Message.GetParam(0).AsUpper()))
                return CONTINUE;
            return HALT;
        }
        if (!pClient->HasBatch()) {
            // Clients without batch must see neither the framing nor the
            // tag. ZNC only filters tags for clients without message-tags,
            // so strip it here for message-tags clients too.
            if (sCmd.Equals("BATCH")) return HALT;
            Message.GetTags().erase("batch");
        }
        if (sCmd.Equals("SETNAME") && !m_Caps.Has(pClient, kSetName)) return HALT;
        if (NoImplicitNames(pClient) && (sCmd == "353" || sCmd == "366")) {
            // 353: <nick> <sym> <chan> :names ; 366: <nick> <chan> :end
            CString sChan = (sCmd == "353" ? Message.GetParam(2) : Message.GetParam(1)).AsLower();
            std::set<CString>* pss = m_mNamesWanted.Find(pClient);
            bool bWanted = pss && (pss->count(sChan) || pss->count("*"));
            if (!bWanted) return HALT;
            if (sCmd == "366") { pss->erase(sChan); pss->erase("*"); }
        }
        if (sCmd.Equals("BATCH") && !m_mEchoBatches.empty()) {
            const time_t tNow = time(nullptr);
            for (auto it = m_mEchoBatches.begin(); it != m_mEchoBatches.end();)
                it = (tNow - it->second.tSent > 60) ? m_mEchoBatches.erase(it) : std::next(it);
            auto eb = m_mEchoBatches.find(Message.GetParam(0).substr(1));
            if (eb != m_mEchoBatches.end() && eb->second.pClient == pClient &&
                pClient->GetStartTime() == eb->second.uStart && !pClient->HasEchoMessage())
                return HALT;
        }
        if (sCmd.Equals("JOIN") && pClient->IsPlaybackActive() && pClient->HasServerTime()) {
            // Attach replay: ZNC re-sends our JOIN for every channel with
            // the current time. Give it the time of the real join.
            CIRCNetwork* pNet = Message.GetNetwork();
            if (pNet && Message.GetNick().NickEquals(pNet->GetCurNick())) {
                auto it = m_mJoinTime.find(JoinKey(pNet, Message.GetParam(0)));
                if (it != m_mJoinTime.end()) Message.GetTags()["time"] = CUtils::FormatServerTime(it->second);
            }
        }
        return CONTINUE;
    }

    // ---- remember when we joined each channel --------------------------

    void OnJoinMessage(CJoinMessage& Message) override {
        CIRCNetwork* pNet = Message.GetNetwork() ? Message.GetNetwork() : GetNetwork();
        if (pNet && Message.GetNick().NickEquals(pNet->GetCurNick()))
            m_mJoinTime[JoinKey(pNet, Message.GetTarget())] = Message.GetTime();
    }

    // ---- messages: upstream echo, msgid minting ------------------------
    // Server-to-client messages that the core is about to buffer, and the
    // user's own messages that the core echoes to other clients and
    // buffers: both get an id if the upstream did not provide one. When
    // the server echoes our messages, the client's message is forwarded
    // without the core's own echo, and the server's copy is fed back in
    // through the client (see OwnMessage / ServerEcho).

    EModRet OnChanTextMessage(CTextMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnPrivTextMessage(CTextMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnChanActionMessage(CActionMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnPrivActionMessage(CActionMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnChanNoticeMessage(CNoticeMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnPrivNoticeMessage(CNoticeMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnChanTagMessage(CTargetMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnPrivTagMessage(CTargetMessage& M) override { Mint(M); return CONTINUE; }
    EModRet OnUserTextMessage(CTextMessage& M) override { return OwnMessage(M); }
    EModRet OnUserActionMessage(CActionMessage& M) override { return OwnMessage(M); }
    EModRet OnUserNoticeMessage(CNoticeMessage& M) override { return OwnMessage(M); }
    EModRet OnUserTagMessage(CTargetMessage& M) override { return OwnMessage(M); }

    // ---- lines to the server: no ZNC msgids, no re-sent echoes ---------

    EModRet OnSendToIRCMessage(CMessage& Message) override {
        MCString& tags = Message.GetTags();
        auto it = tags.find("msgid");
        if (it != tags.end() && it->second.StartsWith("znc-")) tags.erase(it);
        // A server echo fed back through a client: the core wants to send
        // it upstream again; it already came from there.
        CIRCNetwork* pNet = Message.GetNetwork() ? Message.GetNetwork() : GetNetwork();
        auto sv = m_mSuppress.find(pNet);
        if (sv != m_mSuppress.end()) {
            const CString sKey = EchoKey(Message.GetParam(0), Message.GetParam(1));
            for (auto e = sv->second.begin(); e != sv->second.end(); ++e) {
                if (*e == sKey) {
                    sv->second.erase(e);
                    return HALT;
                }
            }
        }
        return CONTINUE;
    }

    // ---- module command interface --------------------------------------

    void OnModCommand(const CString& sCommand) override {
        const CString sCmd = sCommand.Token(0);
        if (sCmd.Equals("STATUS") || sCmd.Equals("HELP")) {
            PutModule("ircv3base: standard-replies, msgid minting, server batch");
            if (CClient* pClient = GetClient()) {
                PutModule("This client: standard-replies=" +
                          CString(m_Caps.HasOrCore(pClient, kStandardReplies)) +
                          " batch=" + CString(pClient->HasBatch()));
            }
        } else {
            PutModule("Commands: status");
        }
    }

  private:
    // ---- upstream echo-message -----------------------------------------

    static bool UpstreamEcho(CIRCNetwork* pNet) {
        CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
        return pSock && pSock->IsAuthed() && pSock->IsCapAccepted(kEchoMessage);
    }
    // Keyed on the raw text parameter so CTCP actions and TAGMSG match too.
    static CString EchoKey(const CString& sTarget, const CString& sText) { return sTarget.AsLower() + " " + sText; }

    // A client's own message. Always remembered for 30 s so a server copy
    // can be recognised. With upstream echo-message: forward it and stop
    // the core from echoing and buffering it now (the server's echo is fed
    // back instead).
    EModRet OwnMessage(CTargetMessage& M) {
        Mint(M);
        if (m_bRedispatch) return CONTINUE;
        CClient* pClient = M.GetClient() ? M.GetClient() : GetClient();
        CIRCNetwork* pNet = M.GetNetwork() ? M.GetNetwork() : GetNetwork();
        if (!pClient || !pNet || !pNet->IsIRCConnected()) return CONTINUE;
        const CString sTarget = M.GetTarget();
        if (sTarget.empty() || sTarget.StartsWith(pNet->GetUser()->GetStatusPrefix())) return CONTINUE;
        std::vector<PendingEcho>& v = m_mPending[pNet];
        const time_t tNow = time(nullptr);
        for (auto it = v.begin(); it != v.end();) it = (tNow - it->tSent > 30) ? v.erase(it) : std::next(it);
        v.push_back({pClient, pClient->GetStartTime(), EchoKey(sTarget, M.GetParam(1)), tNow});
        if (!UpstreamEcho(pNet)) return CONTINUE;
        pClient->PutIRCStripping(M);
        return HALT;
    }

    // A PRIVMSG/NOTICE/TAGMSG from our own nick arriving from the server:
    // the echo of something a client sent (feed it back through that
    // client), or a message sent from another session. Seen in
    // OnRawMessage because the core hands a message to a third party to no
    // typed hook at all.
    EModRet ServerEcho(CMessage& M, CIRCNetwork* pNet) {
        const CString sTarget = M.GetParam(0), sText = M.GetParam(1);
        const CString sKey = EchoKey(sTarget, sText);
        CClient* pOwner = nullptr;
        bool bMatched = false;
        auto pv = m_mPending.find(pNet);
        if (pv != m_mPending.end()) {
            for (auto it = pv->second.begin(); it != pv->second.end(); ++it) {
                if (it->sKey != sKey) continue;
                bMatched = true;
                const std::vector<CClient*>& vClients = pNet->GetClients();
                if (std::find(vClients.begin(), vClients.end(), it->pClient) != vClients.end() &&
                    it->pClient->GetStartTime() == it->uStart)
                    pOwner = it->pClient;
                pv->second.erase(it);
                break;
            }
        }
        if (!UpstreamEcho(pNet)) {
            // echo-message was not negotiated, yet the server sent our own
            // message back (some ircds do this with vendor caps, e.g.
            // Seedpool's seedpool/enhanced). The core already echoed and
            // buffered it when the client sent it: drop the copy.
            return bMatched ? HALT : CONTINUE;
        }
        if (pOwner) {
            CMessage copy(M);
            copy.SetNick(CNick());
            m_mSuppress[pNet].push_back(sKey);
            m_bRedispatch = true;
            pOwner->ReadLine(copy.ToString());
            m_bRedispatch = false;
            return HALT;
        }
        // No client of ours sent it: a message from another session.
        if (pNet->IsChan(sTarget) || sTarget.Equals(pNet->GetCurNick())) return CONTINUE;  // the core handles these
        // Private message to a third party: the core would only forward it.
        // Buffer it under the target, show it to clients that understand
        // self-messages.
        if (!M.GetCommand().Equals("NOTICE") &&
            (!pNet->GetUser()->AutoClearQueryBuffer() || !pNet->IsUserOnline())) {
            if (CQuery* pQuery = pNet->AddQuery(sTarget)) {
                CMessage Format(M);
                Format.SetNick(CNick(_NAMEDFMT(pNet->GetIRCNick().GetNickMask())));
                Format.SetParam(0, _NAMEDFMT(sTarget));
                if (M.GetParams().size() > 1) Format.SetParam(1, "{text}");
                pQuery->AddBuffer(Format, sText);
            }
        }
        for (CClient* pClient : pNet->GetClients())
            if (pClient->HasEchoMessage() || pClient->HasSelfMessage()) pClient->PutClient(M);
        return HALT;
    }

    static CString JoinKey(const CIRCNetwork* pNet, const CString& sChan) {
        return pNet->GetUser()->GetUsername() + "/" + pNet->GetName() + " " + sChan.AsLower();
    }

    void Mint(CMessage& Message) {
        CIRCNetwork* pNetwork = Message.GetNetwork() ? Message.GetNetwork() : GetNetwork();
        if (!pNetwork) return;
        MCString& tags = Message.GetTags();
        if (!tags["msgid"].empty()) return;
        tags["msgid"] = NextMsgId(pNetwork);
    }

    // "znc-<8 hex of md5(user/network)>-<hex counter>". The counter is kept
    // in the module's NV store, advanced by kFlush on load so a crash can
    // never hand out an id twice.
    CString NextMsgId(CIRCNetwork* pNetwork) {
        static const unsigned long long kFlush = 1000;
        const CString sKey = "msgid:" + pNetwork->GetUser()->GetUsername() + "/" + pNetwork->GetName();
        auto it = m_mCounters.find(sKey);
        if (it == m_mCounters.end()) {
            unsigned long long uStart = GetNV(sKey).ToULongLong() + kFlush;
            SetNV(sKey, CString(uStart));
            it = m_mCounters.emplace(sKey, uStart).first;
        }
        unsigned long long uId = ++it->second;
        if (uId % kFlush == 0) SetNV(sKey, CString(uId + kFlush));
        CString sHex;
        for (unsigned long long v = uId; v; v >>= 4) sHex.insert(0, 1, "0123456789abcdef"[v & 15]);
        return "znc-" + sKey.MD5().substr(0, 8) + "-" + sHex;
    }

    CapTracker m_Caps;
    std::map<CString, unsigned long long> m_mCounters;
    ircv3::ClientMap<CString> m_mPreAway;
    ircv3::ClientMap<std::set<CString>> m_mNamesWanted;
    std::map<CIRCNetwork*, std::set<CString>> m_mMonitored;  // MONITOR list per network (lower-case)
    std::map<CString, timeval> m_mJoinTime;
    std::map<CIRCNetwork*, std::vector<PendingEcho>> m_mPending;  // sent, waiting for the server echo
    std::map<CIRCNetwork*, std::vector<CString>> m_mSuppress;      // echoes being fed back; do not resend
    std::map<CString, PendingEcho> m_mEchoBatches;                 // echoed multiline batch ref -> sender
    bool m_bRedispatch = false;
};

template <>
void TModInfo<CIrcv3Base>(CModInfo& Info) {
    Info.SetWikiPage("ircv3base");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CIrcv3Base,
                 "Standard replies, msgid minting and server-side batch "
                 "support for the znc-ircv3 module set")
