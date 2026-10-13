/*
 * labeled — labeled-response for ZNC.
 *
 * Global module. A client that negotiated labeled-response may tag any
 * command with @label=X and expects the response to carry the same label
 * (one line, or a labeled-response batch), or an ACK when there is none.
 *
 * ZNC answers some commands itself (PING, *status and module commands, the
 * znc-ircv3 modules' commands, echo-message echoes) and forwards the rest
 * to the upstream server. The two paths are handled differently:
 *
 *  - ZNC-originated replies are produced synchronously while the client's
 *    line is processed. The first ZNC-originated line (prefix irc.znc.in
 *    or a *status or *module nick, PONG, or the echo of the client's own message)
 *    sent to that client after the command gets the label; if it opens a
 *    batch, the batch carries it. Later ZNC lines are not labeled.
 *  - Forwarded commands: when the upstream server supports
 *    labeled-response, the label is rewritten to a ZNC-private one and the
 *    upstream reply (line or batch) is delivered only to that client with
 *    the original label restored. When the upstream lacks the cap, the
 *    command is forwarded unlabeled and the client gets an immediate ACK.
 *  - A command that produced neither is ACKed when the client's next
 *    command arrives.
 *
 * label tags never leak to other clients or to the upstream server.
 *
 * The label is read in OnUserRawMessage, which other modules may HALT
 * (BOUNCER, CHATHISTORY, ...). ZNC calls global modules in load order, so
 * this module moves itself to the front of the list right after loading;
 * it therefore works wherever it appears in the config.
 */
#include <znc/Modules.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/User.h>

#include <znc/znc.h>

#include "caps.h"
#include "clients.h"

#include <algorithm>
#include <map>

using ircv3::CapTracker;

namespace {
const char* kCap = "labeled-response";
const char* kTag = "label";
const char* kPrefix = "znclbl";  // our upstream labels: znclbl<n>

bool IsZncOriginated(const CMessage& M) {
    const CString& sNick = M.GetNick().GetNick();
    if (M.GetNick().GetHost() == "znc.in" || sNick == "irc.znc.in") return true;
    if (!sNick.empty() && sNick[0] == '*') return true;  // *status, *module
    if (M.GetCommand().Equals("PONG")) return true;
    return false;
}
}  // namespace

class CLabeled : public CModule {
  public:
    MODCONSTRUCTOR(CLabeled) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "labeled must be loaded as a global module";
            return false;
        }
        // Not from inside OnLoad: the core may be iterating the module list.
        AddTimer(MoveToFrontTimer, "labeled-reorder", 1, 1, "Move labeled before the modules that answer commands");
        return true;
    }

    static void MoveToFrontTimer(CModule* pModule, CFPTimer* pTimer) {
        CModules& mods = CZNC::Get().GetModules();
        auto it = std::find(mods.begin(), mods.end(), pModule);
        if (it != mods.end() && it != mods.begin()) std::rotate(mods.begin(), it, it + 1);
    }

    // ---- caps ----------------------------------------------------------

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override { ssCaps.insert(kCap); }
    bool IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState) override {
        return sCap.Equals(kCap);
    }
    void OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) override {
        if (sCap.Equals(kCap)) m_Caps.Set(pClient, sCap, bState);
    }
    bool OnServerCap302Available(const CString& sCap, const CString& sValue) override {
        return sCap.Equals(kCap);
    }
    void OnClientDisconnect() override {
        m_Caps.Forget(GetClient());
        m_mCtx.Erase(GetClient());
        if (m_Echo.pClient == GetClient()) m_Echo = Upstream{nullptr, ""};
        for (auto it = m_mUpstream.begin(); it != m_mUpstream.end();)
            it = it->second.pClient == GetClient() ? m_mUpstream.erase(it) : std::next(it);
    }

    // ---- client command: open a label context --------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return CONTINUE;
        auto& tags = Message.GetTags();
        auto it = tags.find(kTag);
        // A previous command that got no response at all: ACK it now.
        Ctx* pCtx = m_mCtx.Find(pClient);
        if (pCtx && !pCtx->bAnswered) Ack(pClient, pCtx->sLabel);
        m_mCtx.Erase(pClient);
        if (it == tags.end()) return CONTINUE;
        if (!m_Caps.Has(pClient, kCap) || it->second.empty()) {
            tags.erase(it);
            return CONTINUE;
        }
        Ctx c;
        c.sLabel = it->second;
        m_mCtx[pClient] = c;
        return CONTINUE;
    }

    // ---- forwarded to the server ---------------------------------------

    EModRet OnSendToIRCMessage(CMessage& Message) override {
        auto& tags = Message.GetTags();
        CClient* pClient = Message.GetClient();
        Ctx* pCtx = m_mCtx.Find(pClient);
        if (!pCtx || pCtx->bAnswered) {
            tags.erase(kTag);  // never leak a stray label upstream
            return CONTINUE;
        }
        CIRCNetwork* pNet = Message.GetNetwork() ? Message.GetNetwork() : pClient->GetNetwork();
        CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
        if (pSock && pSock->IsCapAccepted(kCap)) {
            CString sUp = kPrefix + CString(++m_uCounter);
            tags[kTag] = sUp;
            m_mUpstream[sUp] = Upstream{pClient, pCtx->sLabel};
            pCtx->bAnswered = true;  // the upstream reply is the response
        } else {
            tags.erase(kTag);
            Ack(pClient, pCtx->sLabel);
            pCtx->bAnswered = true;
        }
        return CONTINUE;
    }

    // ---- upstream replies: route to the owner --------------------------

    EModRet OnRawMessage(CMessage& Message) override {
        auto& tags = Message.GetTags();
        const CString& sCmd = Message.GetCommand();

        // A line inside a batch we own.
        auto bt = tags.find("batch");
        if (bt != tags.end()) {
            auto ob = m_mOwnedBatches.find(bt->second);
            if (ob != m_mOwnedBatches.end()) {
                Route(ob->second, Message);
                return HALT;
            }
        }
        if (sCmd.Equals("BATCH") && Message.GetParam(0).StartsWith("-")) {
            CString sRef = Message.GetParam(0).substr(1);
            auto ob = m_mOwnedBatches.find(sRef);
            if (ob != m_mOwnedBatches.end()) {
                Route(ob->second, Message);
                m_mOwnedBatches.erase(ob);
                return HALT;
            }
        }

        auto lt = tags.find(kTag);
        if (lt == tags.end()) return CONTINUE;
        auto up = m_mUpstream.find(lt->second);
        if (up == m_mUpstream.end()) {
            tags.erase(lt);  // not ours (or already answered): drop the label
            return CONTINUE;
        }
        CClient* pClient = up->second.pClient;
        tags[kTag] = up->second.sLabel;
        m_mUpstream.erase(up);
        // The server's echo of the client's own message (echo-message
        // upstream, see ircv3base), or an echoed multiline batch: everyone
        // gets it through the core; the owner keeps the label.
        CIRCNetwork* pNet = Message.GetNetwork() ? Message.GetNetwork() : GetNetwork();
        bool bOwnNick = pNet && Message.GetNick().NickEquals(pNet->GetCurNick());
        bool bEcho = bOwnNick && (sCmd.Equals("PRIVMSG") || sCmd.Equals("NOTICE") || sCmd.Equals("TAGMSG"));
        bool bEchoBatch = sCmd.Equals("BATCH") && Message.GetParam(0).StartsWith("+") &&
                          Message.GetParam(1).Equals("draft/multiline") && bOwnNick;
        if (bEcho || bEchoBatch) {
            m_Echo = Upstream{pClient, tags[kTag]};
            return CONTINUE;
        }
        if (sCmd.Equals("BATCH") && Message.GetParam(0).StartsWith("+")) {
            m_mOwnedBatches[Message.GetParam(0).substr(1)] = pClient;
        }
        Route(pClient, Message);
        return HALT;
    }

    // ---- lines to clients: label ZNC's own replies, scrub the rest -----

    EModRet OnSendToClientMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient();
        if (!pClient) return CONTINUE;
        auto& tags = Message.GetTags();
        Ctx* pCtx = m_mCtx.Find(pClient);
        auto lt = tags.find(kTag);

        if (lt != tags.end()) {
            // Keep a label only if it is the one this client is waiting for
            // (echo-message echo of its own command, or a routed upstream
            // reply, which we tagged ourselves).
            bool bRouted = m_bRouting;
            if (bRouted) return CONTINUE;
            if (pCtx && !pCtx->bAnswered && lt->second == pCtx->sLabel) {
                pCtx->bAnswered = true;
                m_mCtx.Erase(pClient);
                return CONTINUE;
            }
            if (m_Echo.pClient == pClient && lt->second == m_Echo.sLabel) {
                m_Echo = Upstream{nullptr, ""};
                return CONTINUE;
            }
            tags.erase(lt);
            return CONTINUE;
        }

        if (!pCtx) return CONTINUE;
        Ctx& c = *pCtx;
        const CString& sCmd = Message.GetCommand();
        if (c.bInBatch) {
            if (sCmd.Equals("BATCH") && Message.GetParam(0) == "-" + c.sBatchRef) m_mCtx.Erase(pClient);
            return CONTINUE;
        }
        if (c.bAnswered || !IsZncOriginated(Message)) return CONTINUE;
        tags[kTag] = c.sLabel;
        if (sCmd.Equals("BATCH") && Message.GetParam(0).StartsWith("+")) {
            c.bAnswered = true;
            c.bInBatch = true;
            c.sBatchRef = Message.GetParam(0).substr(1);
        } else {
            m_mCtx.Erase(pClient);
        }
        return CONTINUE;
    }

  private:
    struct Ctx {
        CString sLabel;
        bool bAnswered = false;
        bool bInBatch = false;
        CString sBatchRef;
    };
    struct Upstream {
        CClient* pClient;
        CString sLabel;
    };

    void Ack(CClient* pClient, const CString& sLabel) {
        m_bRouting = true;
        pClient->PutClient("@label=" + sLabel + " :irc.znc.in ACK");
        m_bRouting = false;
    }

    // Deliver a line we labeled ourselves, bypassing the leak filter.
    void Route(CClient* pClient, const CMessage& Message) {
        m_bRouting = true;
        pClient->PutClient(Message);
        m_bRouting = false;
    }

    CapTracker m_Caps;
    ircv3::ClientMap<Ctx> m_mCtx;
    std::map<CString, Upstream> m_mUpstream;
    std::map<CString, CClient*> m_mOwnedBatches;
    Upstream m_Echo{nullptr, ""};  // server echo on its way to the core's broadcast
    unsigned long long m_uCounter = 0;
    bool m_bRouting = false;
};

template <>
void TModInfo<CLabeled>(CModInfo& Info) {
    Info.SetWikiPage("labeled");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CLabeled, "labeled-response: correlate replies with the client command that caused them")
