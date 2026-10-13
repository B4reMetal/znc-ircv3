/*
 * readmarker — draft/read-marker and soju.im/read for ZNC.
 *
 * Global module (capabilities must be offered at CAP LS time, before ZNC
 * knows the user, which only global modules can do). Keeps, per network
 * and target, the timestamp of the last message the user has read, shared
 * across all of the user's clients on that network:
 *
 *   MARKREAD <target> [timestamp=YYYY-MM-DDThh:mm:ss.sssZ]   (draft/read-marker)
 *   READ <target> [timestamp=...]                            (soju.im/read, older)
 *
 * Setting a marker older than the stored one is ignored and the stored one
 * is returned. Changes are broadcast to the network's other clients that
 * negotiated either cap, each in its own dialect. After a client attaches,
 * and whenever the user joins a channel, the stored marker is sent so the
 * client can place its unread line. Markers never go upstream.
 *
 * Storage: module NV, "marker:<user>:<network>:<target>" -> timestamp.
 */
#include <znc/Modules.h>
#include <znc/Chan.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/User.h>

#include "caps.h"
#include "replies.h"

using ircv3::CapTracker;
using ircv3::PutFail;

namespace {
const char* kCapDraft = "draft/read-marker";
const char* kCapSoju = "soju.im/read";
const char* kPrefix = "marker:";

// timestamp=YYYY-MM-DDThh:mm:ss.sssZ (also accept without the "timestamp=").
bool ParseTimestamp(CString s, CString& sOut) {
    s.TrimPrefix("timestamp=");
    if (s.size() != 24 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':' || s[19] != '.' || s[23] != 'Z')
        return false;
    for (size_t i = 0; i < 23; i++) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) continue;
        if (!isdigit((unsigned char)s[i])) return false;
    }
    sOut = s;
    return true;
}
}  // namespace

class CReadMarker : public CModule {
  public:
    MODCONSTRUCTOR(CReadMarker) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "readmarker must be loaded as a global module";
            return false;
        }
        return true;
    }

    // ---- caps ----------------------------------------------------------

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(kCapDraft);
        ssCaps.insert(kCapSoju);
    }
    bool IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState) override {
        return sCap.Equals(kCapDraft) || sCap.Equals(kCapSoju);
    }
    void OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) override {
        if (sCap.Equals(kCapDraft) || sCap.Equals(kCapSoju)) m_Caps.Set(pClient, sCap, bState);
    }
    void OnClientDisconnect() override { m_Caps.Forget(GetClient()); }

    // ---- commands ------------------------------------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        const CString& sCmd = Message.GetCommand();
        bool bDraft = sCmd.Equals("MARKREAD");
        if (!bDraft && !sCmd.Equals("READ")) return CONTINUE;
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return HALT;
        CIRCNetwork* pNet = pClient->GetNetwork();
        const CString sReplyCmd = bDraft ? "MARKREAD" : "READ";
        if (!pNet) {
            PutFail(pClient, sReplyCmd, "INVALID_PARAMS", {}, "Not attached to a network");
            return HALT;
        }

        CString sTarget = Message.GetParam(0);
        if (sTarget.empty()) {
            PutFail(pClient, sReplyCmd, "NEED_MORE_PARAMS", {}, "Missing target");
            return HALT;
        }
        if (Message.GetParams().size() == 1) {
            Send(pClient, sTarget, Get(pNet, sTarget));
            return HALT;
        }
        CString sNew;
        if (!ParseTimestamp(Message.GetParam(1), sNew)) {
            PutFail(pClient, sReplyCmd, "INVALID_PARAMS", {sTarget},
                    "Expected timestamp=YYYY-MM-DDThh:mm:ss.sssZ");
            return HALT;
        }
        CString sOld = Get(pNet, sTarget);
        if (!sOld.empty() && sNew <= sOld) {
            // Only moves forward; tell the client where it actually is.
            Send(pClient, sTarget, sOld);
            return HALT;
        }
        SetNV(Key(pNet, sTarget), sNew);
        Broadcast(pNet, sTarget, sNew);
        return HALT;
    }

    // ---- replay to clients ---------------------------------------------

    void OnClientAttached() override {
        CClient* pClient = GetClient();
        CIRCNetwork* pNet = GetNetwork();
        if (!pClient || !pNet || !HasEither(pClient)) return;
        for (CChan* pChan : pNet->GetChans()) {
            if (pChan->IsDetached()) continue;
            CString sTs = Get(pNet, pChan->GetName());
            if (!sTs.empty()) Send(pClient, pChan->GetName(), sTs);
        }
    }

    // The spec wants the marker after JOIN and before RPL_ENDOFNAMES; the
    // JOIN hook runs before the core forwards the JOIN, so hook 366 instead.
    EModRet OnNumericMessage(CNumericMessage& Message) override {
        CIRCNetwork* pNet = GetNetwork();
        if (!pNet || Message.GetCode() != 366) return CONTINUE;
        const CString sChan = Message.GetParam(1);
        CString sTs = Get(pNet, sChan);
        if (!sTs.empty()) Broadcast(pNet, sChan, sTs);
        return CONTINUE;
    }

    // ---- module commands -----------------------------------------------

    void OnModCommand(const CString& sCommand) override {
        CString sCmd = sCommand.Token(0);
        CIRCNetwork* pNet = GetNetwork();
        if (!pNet) { PutModule("Use this command from a network"); return; }
        const CString sPrefix = Key(pNet, "");
        if (sCmd.Equals("LIST")) {
            CTable t;
            t.AddColumn("Target");
            t.AddColumn("Read up to");
            for (auto it = BeginNV(); it != EndNV(); ++it) {
                if (!it->first.StartsWith(sPrefix)) continue;
                t.AddRow();
                t.SetCell("Target", it->first.substr(sPrefix.size()));
                t.SetCell("Read up to", it->second);
            }
            PutModule(t);
        } else if (sCmd.Equals("CLEAR")) {
            for (auto it = BeginNV(); it != EndNV();) {
                if (it->first.StartsWith(sPrefix)) { auto n = std::next(it); DelNV(it); it = n; }
                else ++it;
            }
            SaveRegistry();
            PutModule("Read markers cleared for " + pNet->GetName());
        } else {
            PutModule("Commands: list, clear");
        }
    }

  private:
    static CString Key(const CIRCNetwork* pNet, const CString& sTarget) {
        return kPrefix + pNet->GetUser()->GetUsername() + ":" + pNet->GetName() + ":" + sTarget.AsLower();
    }
    CString Get(const CIRCNetwork* pNet, const CString& sTarget) const { return GetNV(Key(pNet, sTarget)); }

    bool HasEither(const CClient* pClient) const {
        return m_Caps.Has(pClient, kCapDraft) || m_Caps.Has(pClient, kCapSoju);
    }

    // sTs empty means "no marker known" -> "*".
    void Send(CClient* pClient, const CString& sTarget, const CString& sTs) {
        const CString sVal = sTs.empty() ? "*" : "timestamp=" + sTs;
        if (m_Caps.Has(pClient, kCapDraft))
            pClient->PutClient(":irc.znc.in MARKREAD " + sTarget + " " + sVal);
        else
            pClient->PutClient(":irc.znc.in READ " + sTarget + " " + sVal);
    }

    void Broadcast(CIRCNetwork* pNet, const CString& sTarget, const CString& sTs) {
        for (CClient* pClient : pNet->GetClients())
            if (HasEither(pClient)) Send(pClient, sTarget, sTs);
    }

    CapTracker m_Caps;
};

template <>
void TModInfo<CReadMarker>(CModInfo& Info) {
    Info.SetWikiPage("readmarker");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CReadMarker, "draft/read-marker and soju.im/read: share the read position between clients")
