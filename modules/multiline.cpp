/*
 * multiline — draft/multiline for ZNC.
 *
 * Global module. Offers draft/multiline to clients and requests it from
 * servers. Multiline batches are passed through in both directions:
 *
 *  - server -> client: ZNC's core delivers every inner PRIVMSG; the BATCH
 *    framing and batch tags of multiline batches are passed on only to
 *    clients that negotiated draft/multiline, others get the individual
 *    lines.
 *  - client -> server: when the upstream server negotiated draft/multiline
 *    the client's batch is forwarded as is. When it did not, the batch
 *    framing is dropped and the inner lines are sent as ordinary messages
 *    (which is what the client would have done without the cap).
 *
 * Limits advertised to clients: max-bytes=4096,max-lines=100.
 */
#include <znc/Modules.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>

#include "caps.h"
#include "clients.h"

#include <deque>
#include <map>
#include <set>

using ircv3::CapTracker;

namespace {
const char* kCap = "draft/multiline";
const char* kCapValue = "max-bytes=4096,max-lines=100";
}  // namespace

class CMultiline : public CModule {
  public:
    MODCONSTRUCTOR(CMultiline) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "multiline must be loaded as a global module";
            return false;
        }
        return true;
    }

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(pClient->HasCap302() ? CString(kCap) + "=" + kCapValue : CString(kCap));
    }
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
        m_mFlattened.Erase(GetClient());
        for (auto& kv : m_mClientRefs)
            if (kv.second == GetClient()) kv.second = nullptr;
    }

    // Remember upstream multiline batch refs so the framing can be hidden
    // from clients without the cap (the close line is filtered per client
    // after this hook, so refs are kept for a while instead of erased).
    EModRet OnRawMessage(CMessage& Message) override {
        if (!Message.GetCommand().Equals("BATCH")) return CONTINUE;
        CString sRef = Message.GetParam(0);
        if (sRef.StartsWith("+") && Message.GetParam(1).Equals(kCap)) {
            m_ssUpstreamRefs.insert(sRef.substr(1));
            m_dqUpstreamRefs.push_back(sRef.substr(1));
            while (m_dqUpstreamRefs.size() > 256) {
                m_ssUpstreamRefs.erase(m_dqUpstreamRefs.front());
                m_dqUpstreamRefs.pop_front();
            }
        }
        return CONTINUE;
    }

    EModRet OnSendToClientMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient();
        if (!pClient) return CONTINUE;
        auto& tags = Message.GetTags();
        bool bCapable = m_Caps.Has(pClient, kCap);
        if (Message.GetCommand().Equals("BATCH")) {
            CString sRef = Message.GetParam(0).substr(1);
            if (!bCapable && m_ssUpstreamRefs.count(sRef)) return HALT;
            return CONTINUE;
        }
        auto bt = tags.find("batch");
        if (bt == tags.end()) return CONTINUE;
        // Upstream multiline batch: framing is hidden from clients without
        // the cap. Client-originated batch (ZNC's echo to the user's other
        // clients): only the sender itself ever saw that batch, so the tag
        // is stripped for everyone else.
        auto cr = m_mClientRefs.find(bt->second);
        bool bStrip = (!bCapable && m_ssUpstreamRefs.count(bt->second)) ||
                      (cr != m_mClientRefs.end() && cr->second != pClient);
        if (bStrip) {
            tags.erase(bt);
            tags.erase("draft/multiline-concat");
        }
        return CONTINUE;
    }

    EModRet OnUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return CONTINUE;
        CIRCNetwork* pNet = pClient->GetNetwork();
        CIRCSock* pSock = pNet ? pNet->GetIRCSock() : nullptr;
        bool bUpstream = pSock && pSock->IsCapAccepted(kCap);
        auto& tags = Message.GetTags();

        if (Message.GetCommand().Equals("BATCH")) {
            CString sRef = Message.GetParam(0);
            if (sRef.StartsWith("+") && Message.GetParam(1).Equals(kCap)) {
                if (bUpstream) {
                    m_mClientRefs[sRef.substr(1)] = pClient;
                    m_dqClientRefs.push_back(sRef.substr(1));
                    while (m_dqClientRefs.size() > 256) {
                        m_mClientRefs.erase(m_dqClientRefs.front());
                        m_dqClientRefs.pop_front();
                    }
                    return CONTINUE;
                }
                m_mFlattened[pClient].insert(sRef.substr(1));
                return HALT;
            }
            if (sRef.StartsWith("-")) {
                std::set<CString>* pss = m_mFlattened.Find(pClient);
                if (pss && pss->erase(sRef.substr(1))) return HALT;
            }
            return CONTINUE;
        }
        // Inner line of a batch we are flattening: drop the framing tags so
        // the core treats it as a normal message.
        auto bt = tags.find("batch");
        if (bt != tags.end()) {
            std::set<CString>* pss = m_mFlattened.Find(pClient);
            if (pss && pss->count(bt->second)) {
                tags.erase(bt);
                tags.erase("draft/multiline-concat");
            }
        }
        return CONTINUE;
    }

  private:
    CapTracker m_Caps;
    ircv3::ClientMap<std::set<CString>> m_mFlattened;
    std::set<CString> m_ssUpstreamRefs;
    std::deque<CString> m_dqUpstreamRefs;
    std::map<CString, CClient*> m_mClientRefs;
    std::deque<CString> m_dqClientRefs;
};

template <>
void TModInfo<CMultiline>(CModInfo& Info) {
    Info.SetWikiPage("multiline");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CMultiline, "draft/multiline pass-through with flattening for servers without it")
