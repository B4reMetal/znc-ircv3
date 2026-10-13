// Per-client capability bookkeeping for modules.
//
// ZNC tells a module which caps a client enabled through OnClientCapRequest,
// but does not remember them on the module's behalf. CClient::IsCapEnabled()
// does know, but only after the ACK has been processed; keeping our own map
// also lets a module answer "does this client have cap X" from hooks that
// only receive a CMessage.
#pragma once
#include <znc/Client.h>
#include <znc/ZNCString.h>
#include <set>

#include "clients.h"

namespace ircv3 {

class CapTracker {
  public:
    void Set(CClient* pClient, const CString& sCap, bool bState) {
        if (!pClient) return;
        if (bState)
            m_mCaps[pClient].insert(sCap);
        else
            m_mCaps[pClient].erase(sCap);
    }
    bool Has(const CClient* pClient, const CString& sCap) const {
        const std::set<CString>* p = m_mCaps.Find(pClient);
        return p && p->count(sCap) == 1;
    }
    // Either our record or ZNC's own view: ZNC knows about core caps and
    // about caps a module accepted; ours is authoritative for the latter
    // but asking both is cheap.
    bool HasOrCore(const CClient* pClient, const CString& sCap) const {
        return Has(pClient, sCap) || (pClient && pClient->IsCapEnabled(sCap));
    }
    void Forget(CClient* pClient) { m_mCaps.Erase(pClient); }

  private:
    ClientMap<std::set<CString>> m_mCaps;
};

}  // namespace ircv3
