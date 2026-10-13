// Per-client state for modules.
//
// ZNC only tells a module about a client going away through
// OnClientDisconnect, which is not called for connections that never
// logged in. State keyed by CClient* alone could therefore be inherited by
// a later connection whose object happens to get the same address. Entries
// here remember the socket's start time and are treated as absent when it
// no longer matches.
#pragma once
#include <znc/Client.h>
#include <cstdint>
#include <map>

namespace ircv3 {

template <class T>
class ClientMap {
  public:
    // Returns the entry for pClient, creating a fresh one if there is none
    // (or a stale one from an earlier connection).
    T& operator[](CClient* pClient) {
        auto it = m_m.find(pClient);
        if (it == m_m.end() || it->second.uStart != pClient->GetStartTime()) {
            it = m_m.insert_or_assign(pClient, Entry{pClient->GetStartTime(), T()}).first;
        }
        return it->second.value;
    }
    T* Find(const CClient* pClient) {
        if (!pClient) return nullptr;
        auto it = m_m.find(const_cast<CClient*>(pClient));
        if (it == m_m.end() || it->second.uStart != pClient->GetStartTime()) return nullptr;
        return &it->second.value;
    }
    const T* Find(const CClient* pClient) const {
        return const_cast<ClientMap*>(this)->Find(pClient);
    }
    bool Has(const CClient* pClient) const { return Find(pClient) != nullptr; }
    void Erase(const CClient* pClient) { m_m.erase(const_cast<CClient*>(pClient)); }

  private:
    struct Entry {
        uint64_t uStart;
        T value;
    };
    std::map<CClient*, Entry> m_m;
};

}  // namespace ircv3
