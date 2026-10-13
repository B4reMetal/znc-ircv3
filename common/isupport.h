// ZNC-side ISUPPORT tokens (RPL_ISUPPORT, 005).
//
// Clients treat the end of the MOTD (376/422) as "registration done" and
// act on the ISUPPORT tokens they have by then, so a module's tokens must
// be part of the burst ZNC replays on attach (001 ... 005 ... 376), not
// trail it. ISupportBurst watches the lines sent to a client: a 001 opens
// a burst, and the module's 005 line is sent right before the 376/422
// that closes it. For a network that is not connected ZNC sends a lone
// "001 Welcome to ZNC"; OnAttached() then sends the tokens after it.
//
// Tokens the module owns are also removed from the upstream server's 005
// lines, since the module answers those commands itself.
#pragma once
#include <znc/Client.h>
#include <znc/Message.h>
#include <znc/Modules.h>
#include <znc/ZNCString.h>
#include <functional>
#include <map>
#include <set>

#include "clients.h"

namespace ircv3 {

inline void SendISupport(CClient* pClient, const MCString& mssTokens) {
    if (!pClient || mssTokens.empty()) return;
    CString sLine = ":irc.znc.in 005 " + pClient->GetNick();
    for (const auto& kv : mssTokens) {
        sLine += " " + kv.first;
        if (!kv.second.empty()) sLine += "=" + kv.second;
    }
    sLine += " :are supported by this server";
    pClient->PutClient(sLine);
}

class ISupportBurst {
  public:
    using TokenFn = std::function<MCString(CClient*)>;

    // ssOwn: token names this module owns (stripped from upstream 005).
    explicit ISupportBurst(std::set<CString> ssOwn) : m_ssOwn(std::move(ssOwn)) {}

    // From OnSendToClientMessage. May send the module's 005 line; returns
    // HALT when an upstream 005 line is left without tokens.
    CModule::EModRet OnSend(CMessage& Message, const TokenFn& tokens) {
        CClient* pClient = Message.GetClient();
        if (!pClient) return CModule::CONTINUE;
        const CString& sCmd = Message.GetCommand();
        if (sCmd == "001") {
            m_mPending[pClient] = true;
            return CModule::CONTINUE;
        }
        if (sCmd == "005") {
            if (Message.GetNick().GetNick() == "irc.znc.in") return CModule::CONTINUE;
            VCString vs = Message.GetParams();
            bool bChanged = false;
            for (size_t i = 1; i + 1 < vs.size();) {
                if (m_ssOwn.count(vs[i].Token(0, false, "="))) {
                    vs.erase(vs.begin() + i);
                    bChanged = true;
                } else {
                    ++i;
                }
            }
            if (!bChanged) return CModule::CONTINUE;
            if (vs.size() <= 2) return CModule::HALT;
            Message.SetParams(vs);
            return CModule::CONTINUE;
        }
        if (sCmd == "376" || sCmd == "422") {
            bool* pb = m_mPending.Find(pClient);
            if (!pb || !*pb) return CModule::CONTINUE;
            *pb = false;
            SendISupport(pClient, tokens(pClient));
        }
        return CModule::CONTINUE;
    }

    // From OnClientAttached: closes a burst that had no 376/422.
    void OnAttached(CClient* pClient, const TokenFn& tokens) {
        bool* pb = m_mPending.Find(pClient);
        if (!pb || !*pb) return;
        *pb = false;
        SendISupport(pClient, tokens(pClient));
    }

    void Forget(CClient* pClient) { m_mPending.Erase(pClient); }

  private:
    std::set<CString> m_ssOwn;
    ClientMap<bool> m_mPending;
};

}  // namespace ircv3
