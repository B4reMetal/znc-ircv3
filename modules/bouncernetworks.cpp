/*
 * bouncernetworks — soju.im/bouncer-networks for ZNC.
 *
 * Global module. Lets IRCv3 clients discover, bind to, add, change and
 * delete the user's networks over the IRC connection instead of the
 * user/network login syntax. Spec: soju's doc/ext/bouncer-networks.md.
 *
 *   caps     soju.im/bouncer-networks, soju.im/bouncer-networks-notify
 *   ISUPPORT BOUNCER_NETID=<id> on connections bound to a network
 *   commands BOUNCER BIND|LISTNETWORKS|ADDNETWORK|CHANGENETWORK|DELNETWORK
 *   batch    soju.im/bouncer-networks (LISTNETWORKS, initial notify list)
 *   replies  FAIL BOUNCER <code> ...
 *
 * Network ids are integers allocated once per network and persisted in the
 * module's NV store as "id:<user>:<network>" (plus "next"). They survive
 * renames because the live map is keyed by CIRCNetwork* and rewritten on
 * every change.
 *
 * Binding follows soju: a connection that negotiated the cap and sent no
 * BIND (and named no network in its username) stays *unbound*: it gets a
 * minimal registration from irc.znc.in, the network list, and no channel
 * traffic. Clients like goguma use that connection to discover networks
 * and then open one BIND connection per network.
 *
 * ZNC's "You have several networks configured ... Selecting network X"
 * status notices are written straight to the socket, bypassing module
 * hooks. To keep them away from bouncer-networks clients, the login
 * credentials of such a client are rewritten pre-registration to name the
 * user's first network (user/network), which makes the core skip the
 * notices; the real binding is applied afterwards as described below.
 * Whether a client uses the cap is only known once it has requested it,
 * which may happen after PASS/USER, so those lines are held back while
 * capability negotiation is open and replayed (rewritten if needed) when
 * CAP END arrives.
 *
 * ZNC attaches a client to a network inside AcceptLogin before any module
 * runs, so a BIND to a different network (or the unbound state) is applied
 * from OnClientLogin with CClient::SetNetwork. Everything the core sends
 * to the client for the wrong network in between (welcome replay, joins,
 * cap notifications) is swallowed in OnSendToClientMessage, so the client
 * only ever sees the right replay. A core hook to choose the network at
 * login would make this unnecessary.
 *
 * The server password is accepted in ADDNETWORK/CHANGENETWORK but never
 * sent back in NETWORK lines.
 */
#include <znc/Modules.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/Server.h>
#include <znc/User.h>
#include <znc/znc.h>

#include "caps.h"
#include "clients.h"
#include "ids.h"
#include "isupport.h"
#include "msgtag.h"
#include "replies.h"

#include <algorithm>
#include <map>

using ircv3::CapTracker;
using ircv3::PutFail;

namespace {
const char* kCap = "soju.im/bouncer-networks";
const char* kCapNotify = "soju.im/bouncer-networks-notify";
const char* kBatchType = "soju.im/bouncer-networks";
}  // namespace

class CBouncerNetworks : public CModule {
  public:
    MODCONSTRUCTOR(CBouncerNetworks) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "bouncernetworks must be loaded as a global module";
            return false;
        }
        m_uNext = GetNV("next").ToUInt();
        if (m_uNext == 0) m_uNext = 1;
        for (const auto& u : CZNC::Get().GetUserMap())
            for (CIRCNetwork* pNet : u.second->GetNetworks()) IdOf(pNet);
        return true;
    }

    // ---- capabilities --------------------------------------------------

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(kCap);
        ssCaps.insert(kCapNotify);
    }

    bool IsClientCapSupported(CClient* pClient, const CString& sCap,
                              bool bState) override {
        return sCap.Equals(kCap) || sCap.Equals(kCapNotify);
    }

    void OnClientCapRequest(CClient* pClient, const CString& sCap,
                            bool bState) override {
        if (!sCap.Equals(kCap) && !sCap.Equals(kCapNotify)) return;
        m_Caps.Set(pClient, sCap, bState);
        // A late REQ of the notify cap after login gets the list right away.
        if (bState && sCap.Equals(kCapNotify) && pClient->IsAttached())
            SendNetworkList(pClient, pClient->GetUser());
    }

    void OnClientDisconnect() override {
        m_Caps.Forget(GetClient());
        m_mClients.Erase(GetClient());
        m_Burst.Forget(GetClient());
    }

    MCString ISupportFor(CClient* pClient) {
        if (!m_Caps.Has(pClient, kCap) || !pClient->GetNetwork()) return {};
        return {{"BOUNCER_NETID", CString(IdOf(pClient->GetNetwork()))}};
    }

    void OnClientAttached() override {
        m_Burst.OnAttached(GetClient(), [this](CClient* p) { return ISupportFor(p); });
    }

    // ---- pre-registration: BOUNCER BIND --------------------------------

    EModRet OnUnknownUserRawMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient();
        if (!pClient) return CONTINUE;
        const CString& sCmd = Message.GetCommand();
        ClientState& st = m_mClients[pClient];
        const bool bCap = m_Caps.Has(pClient, kCap);
        if (sCmd.Equals("CAP")) {
            const CString sSub = Message.GetParam(0).AsUpper();
            if (sSub == "LS" || sSub == "REQ") st.bInCap = true;
            if (sSub == "END" && !st.vsHeld.empty()) {
                // Replay PASS/USER now that the caps are known.
                VCString vsHeld;
                vsHeld.swap(st.vsHeld);
                st.bReplaying = true;
                for (const CString& sLine : vsHeld) pClient->ReadLine(sLine);
                ClientState* pSt = m_mClients.Find(pClient);
                if (!pSt) return CONTINUE;
                pSt->bReplaying = false;
                if (m_Caps.Has(pClient, kCap) && pSt->uPending == 0 && !pSt->bExplicitNetwork) pSt->bUnbound = true;
                return CONTINUE;
            }
            if (sSub == "END") {
                if (bCap && st.uPending == 0 && !st.bExplicitNetwork) st.bUnbound = true;
                return CONTINUE;
            }
            return CONTINUE;
        }
        if ((sCmd.Equals("PASS") || sCmd.Equals("USER")) && st.bInCap && !st.bReplaying &&
            !pClient->IsAttached()) {
            st.vsHeld.push_back(Message.ToString());
            if (sCmd.Equals("PASS")) st.bAuthSeen = true;  // credentials given, just deferred
            return HALT;
        }
        if (sCmd.Equals("PASS")) {
            st.bAuthSeen = true;
            CString sArg = Message.GetParam(0);
            if (NamesNetwork(sArg)) {
                st.bExplicitNetwork = true;
            } else if (bCap && sArg.Contains(":")) {
                // user[@id]:pass -> user[@id]/firstnet:pass
                CString sUser = sArg.Token(0, false, ":"), sPass = sArg.Token(1, true, ":");
                CString sNet = FirstNetworkOf(sUser.Token(0, false, "@"));
                if (!sNet.empty()) Message.SetParam(0, sUser + "/" + sNet + ":" + sPass);
            }
            return CONTINUE;
        }
        if (sCmd.Equals("USER")) {
            CString sArg = Message.GetParam(0);
            if (NamesNetwork(sArg)) {
                st.bExplicitNetwork = true;
            } else if (bCap) {
                CString sNet = FirstNetworkOf(sArg.Token(0, false, "@"));
                if (!sNet.empty()) Message.SetParam(0, sArg + "/" + sNet);
            }
            return CONTINUE;
        }
        if (sCmd.Equals("AUTHENTICATE")) {
            st.bAuthSeen = true;
            // PLAIN payload: authzid \0 authcid \0 password; either id may
            // carry /network. ZNC takes user/network from the authzid.
            CString sArg = Message.GetParam(0);
            if (sArg == "PLAIN" || sArg == "+" || sArg == "*" || sArg.size() > 390) return CONTINUE;
            CString sPayload = sArg.Base64Decode_n();
            // CString::Split cannot take a NUL delimiter; split by hand.
            VCString vs;
            for (size_t uPos = 0;;) {
                size_t uNul = sPayload.find('\0', uPos);
                vs.push_back(sPayload.substr(uPos, uNul == CString::npos ? CString::npos : uNul - uPos));
                if (uNul == CString::npos) break;
                uPos = uNul + 1;
            }
            if (vs.size() != 3) return CONTINUE;
            if (vs[0].Contains("/") || vs[1].Contains("/")) {
                st.bExplicitNetwork = true;
            } else if (bCap && (vs[0].empty() || vs[0] == vs[1])) {
                CString sNet = FirstNetworkOf(vs[1].Token(0, false, "@"));
                if (!sNet.empty()) {
                    CString sNew = vs[1] + "/" + sNet + CString("\0", 1) + vs[1] + CString("\0", 1) + vs[2];
                    Message.SetParam(0, sNew.Base64Encode_n());
                }
            }
            return CONTINUE;
        }
        if (!sCmd.Equals("BOUNCER")) return CONTINUE;

        CString sSub = Message.GetParam(0).AsUpper();
        if (sSub == "BIND") {
            if (!st.bAuthSeen && pClient->HasCap302()) {
                PutFail(pClient, "BOUNCER", "ACCOUNT_REQUIRED", {"BIND"},
                        "Authenticate (PASS or SASL) before BOUNCER BIND");
                return HALT;
            }
            unsigned uId = Message.GetParam(1).ToUInt();
            if (uId == 0) {
                PutFail(pClient, "BOUNCER", "INVALID_NETID", {"BIND", Message.GetParam(1)},
                        "Invalid network id");
                return HALT;
            }
            st.uPending = uId;
            return HALT;
        }
        PutFail(pClient, "BOUNCER", "ACCOUNT_REQUIRED", {sSub}, "Log in first");
        return HALT;
    }

    // ---- login: apply the binding, announce ----------------------------

    void OnClientLogin() override {
        CClient* pClient = GetClient();
        if (!pClient) return;
        CUser* pUser = pClient->GetUser();
        ClientState& st = m_mClients[pClient];

        if (st.uPending) {
            unsigned uWanted = st.uPending;
            CIRCNetwork* pNet = FindById(pUser, uWanted);
            if (!pNet) {
                st.uPending = 0;
                PutFail(pClient, "BOUNCER", "INVALID_NETID", {"BIND", CString(uWanted)},
                        "Unknown network id");
                pClient->Close(Csock::CLT_AFTERWRITE);
                return;
            }
            if (pClient->GetNetwork() != pNet) {
                // The core already attached us to its own choice, but the
                // client never saw it (see OnSendToClientMessage). Detach
                // properly (modules withdraw what they announced; the PARTs
                // are swallowed) and attach with the full replay for pNet.
                pClient->SetNetwork(pNet, true, true);
            }
            st.uPending = 0;  // stop swallowing output
        }

        if (st.bUnbound) {
            // Leave the core's network with everything swallowed, then send
            // our own registration block for the network-less connection.
            st.bSwitching = true;
            if (pClient->GetNetwork()) pClient->SetNetwork(nullptr, true, true);
            st.bSwitching = false;
            st.bUnbound = false;
            const CString n = pClient->GetNick();
            pClient->PutClient(":irc.znc.in 001 " + n + " :Welcome to ZNC");
            pClient->PutClient(":irc.znc.in 002 " + n + " :Your host is irc.znc.in, running ZNC " + CZNC::GetVersion());
            pClient->PutClient(":irc.znc.in 003 " + n + " :This connection is not bound to a network");
            pClient->PutClient(":irc.znc.in 004 " + n + " irc.znc.in znc-ircv3 i i");
            pClient->PutClient(":irc.znc.in 005 " + n + " NETWORK=ZNC CASEMAPPING=ascii CHANTYPES=# :are supported by this server");
            pClient->PutClient(":irc.znc.in 422 " + n + " :MOTD File is missing");
        }
        if (m_Caps.Has(pClient, kCapNotify)) SendNetworkList(pClient, pUser);
    }

    // Swallow the core's attach output for a network the client did not
    // BIND to (between AcceptLogin and OnClientLogin), and place
    // BOUNCER_NETID inside the registration burst.
    EModRet OnSendToClientMessage(CMessage& Message) override {
        CClient* pClient = Message.GetClient();
        if (!pClient) return CONTINUE;
        if (const ClientState* pSt = m_mClients.Find(pClient)) {
            CIRCNetwork* pNet = Message.GetNetwork();
            // Network-less lines pass (a refused login's 464, FAIL replies)
            // except while the core's own network is being left.
            if (pSt->bSwitching) return HALT;
            if (pSt->bUnbound && pNet) return HALT;
            if (pSt->uPending && pNet && IdOf(pNet) != pSt->uPending) return HALT;
        }
        return m_Burst.OnSend(Message, [this](CClient* p) { return ISupportFor(p); });
    }

    // ---- post-login commands -------------------------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        if (!Message.GetCommand().Equals("BOUNCER")) return CONTINUE;
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        CUser* pUser = pClient ? pClient->GetUser() : nullptr;
        if (!pClient || !pUser) return HALT;

        CString sSub = Message.GetParam(0).AsUpper();
        if (sSub == "BIND") {
            PutFail(pClient, "BOUNCER", "REGISTRATION_IS_COMPLETED", {"BIND"},
                    "BIND must be sent before registration completes");
        } else if (sSub == "LISTNETWORKS") {
            SendNetworkList(pClient, pUser);
        } else if (sSub == "ADDNETWORK") {
            AddNetwork(pClient, pUser, Message.GetParam(1));
        } else if (sSub == "CHANGENETWORK") {
            ChangeNetwork(pClient, pUser, Message.GetParam(1), Message.GetParam(2));
        } else if (sSub == "DELNETWORK") {
            DelNetwork(pClient, pUser, Message.GetParam(1));
        } else {
            PutFail(pClient, "BOUNCER", "UNKNOWN_COMMAND", {sSub.empty() ? "*" : sSub},
                    "Unknown subcommand");
        }
        return HALT;
    }

    // ---- network lifecycle -> notifications ----------------------------

    EModRet OnAddNetwork(CIRCNetwork& Network, CString& sErrorRet) override {
        // Called before the network is in the user's list; allocate lazily
        // on first notify instead. Nothing to do here.
        return CONTINUE;
    }

    EModRet OnDeleteNetwork(CIRCNetwork& Network) override {
        unsigned uId = IdOf(&Network);
        // Clients bound to it would have their sockets destroyed with the
        // network; detach them first so the notification is delivered.
        const CString sLine = ":irc.znc.in BOUNCER NETWORK " + CString(uId) + " *";
        std::vector<CClient*> vClients = Network.GetClients();
        for (CClient* pClient : vClients) {
            pClient->PutStatusNotice("Network " + Network.GetName() + " was deleted");
            if (m_Caps.Has(pClient, kCapNotify)) pClient->PutClient(sLine);
            pClient->SetNetwork(nullptr, true, false);
        }
        // Detached clients are in neither list GetAllClients() builds from.
        for (CClient* pClient : Network.GetUser()->GetAllClients())
            if (m_Caps.Has(pClient, kCapNotify) &&
                std::find(vClients.begin(), vClients.end(), pClient) == vClients.end())
                pClient->PutClient(sLine);
        m_mIds.erase(&Network);
        m_mErrors.erase(&Network);
        SaveIds(Network.GetUser());
        return CONTINUE;
    }

    EModRet OnIRCConnecting(CIRCSock* pIRCSock) override {
        if (CIRCNetwork* pNet = GetNetwork()) NotifyChange(pNet, {{"state", "connecting"}});
        return CONTINUE;
    }

    void OnIRCConnected() override {
        if (CIRCNetwork* pNet = GetNetwork()) {
            MCString mss = {{"state", "connected"}};
            if (m_mErrors.erase(pNet)) mss["error"] = "";  // attribute removed
            NotifyChange(pNet, mss);
        }
    }

    void OnIRCDisconnected() override {
        if (CIRCNetwork* pNet = GetNetwork()) {
            MCString mss = {{"state", "disconnected"}};
            auto it = m_mErrors.find(pNet);
            if (it != m_mErrors.end()) mss["error"] = it->second;
            NotifyChange(pNet, mss);
        }
    }

    void OnIRCConnectionError(CIRCSock* pIRCSock) override {
        if (CIRCNetwork* pNet = GetNetwork()) m_mErrors[pNet] = "Connection error";
    }

    // ---- module commands -----------------------------------------------

    void OnModCommand(const CString& sCommand) override {
        CString sCmd = sCommand.Token(0);
        if (sCmd.Equals("LIST")) {
            CUser* pUser = GetUser();
            if (!pUser) { PutModule("No user context"); return; }
            CTable t;
            t.AddColumn("Id");
            t.AddColumn("Network");
            t.AddColumn("State");
            for (CIRCNetwork* pNet : pUser->GetNetworks()) {
                t.AddRow();
                t.SetCell("Id", CString(IdOf(pNet)));
                t.SetCell("Network", pNet->GetName());
                t.SetCell("State", State(pNet));
            }
            PutModule(t);
        } else {
            PutModule("Commands: list");
        }
    }

  private:
    struct ClientState {
        bool bAuthSeen = false;
        bool bExplicitNetwork = false;  // user/network in PASS, USER or SASL
        bool bUnbound = false;          // cap, no BIND, no explicit network
        bool bInCap = false;            // CAP LS/REQ seen before registration
        bool bReplaying = false;        // held lines being fed back in
        bool bSwitching = false;        // inside SetNetwork(nullptr): swallow everything
        VCString vsHeld;                // PASS/USER held until CAP END
        unsigned uPending = 0;
    };

    static bool NamesNetwork(const CString& sUserField) {
        // user[@client][/network]
        return sUserField.Token(0, false, ":").Contains("/");
    }

    static CString FirstNetworkOf(const CString& sUsername) {
        CUser* pUser = CZNC::Get().FindUser(sUsername);
        if (!pUser || pUser->GetNetworks().empty()) return "";
        return pUser->GetNetworks()[0]->GetName();
    }

    // ---- ids ----------------------------------------------------------

    static CString Key(const CIRCNetwork* pNet) {
        return "id:" + pNet->GetUser()->GetUsername() + ":" + pNet->GetName();
    }

    unsigned IdOf(CIRCNetwork* pNet) {
        auto it = m_mIds.find(pNet);
        if (it != m_mIds.end()) return it->second;
        unsigned uId = GetNV(Key(pNet)).ToUInt();
        if (uId == 0) {
            uId = m_uNext++;
            SetNV("next", CString(m_uNext));
        }
        m_mIds[pNet] = uId;
        SaveIds(pNet->GetUser());
        return uId;
    }

    // Rewrite the "id:<user>:*" entries from the live map so renames keep
    // their id; entries for networks that no longer exist are dropped.
    void SaveIds(CUser* pUser) {
        const CString sPrefix = "id:" + pUser->GetUsername() + ":";
        for (auto it = BeginNV(); it != EndNV();) {
            if (it->first.StartsWith(sPrefix) && !pUser->FindNetwork(it->first.substr(sPrefix.size()))) {
                auto next = std::next(it);
                DelNV(it);
                it = next;
            } else {
                ++it;
            }
        }
        for (CIRCNetwork* pNet : pUser->GetNetworks()) {
            auto it = m_mIds.find(pNet);
            if (it != m_mIds.end()) SetNV(Key(pNet), CString(it->second), false);
        }
        SaveRegistry();
    }

    CIRCNetwork* FindById(CUser* pUser, unsigned uId) {
        for (CIRCNetwork* pNet : pUser->GetNetworks())
            if (IdOf(pNet) == uId) return pNet;
        return nullptr;
    }

    // ---- attributes ---------------------------------------------------

    static CString State(const CIRCNetwork* pNet) {
        if (pNet->IsIRCConnected()) return "connected";
        if (pNet->GetIRCSock()) return "connecting";
        return "disconnected";
    }

    MCString Attrs(CIRCNetwork* pNet) {
        MCString mss;
        mss["name"] = pNet->GetName();
        mss["state"] = State(pNet);
        const std::vector<CServer*>& vServers = pNet->GetServers();
        if (!vServers.empty()) {
            CServer* pServer = pNet->GetCurrentServer() ? pNet->GetCurrentServer() : vServers[0];
            mss["host"] = pServer->GetName();
            mss["port"] = CString(pServer->GetPort());
            mss["tls"] = pServer->IsSSL() ? "1" : "0";
            // pass is write-only: never echo the server password.
        }
        mss["nickname"] = pNet->GetNick();
        mss["username"] = pNet->GetIdent();
        mss["realname"] = pNet->GetRealName();
        auto it = m_mErrors.find(pNet);
        if (it != m_mErrors.end()) mss["error"] = it->second;
        return mss;
    }

    static CString NetworkLine(unsigned uId, const MCString& mssAttrs) {
        return ":irc.znc.in BOUNCER NETWORK " + CString(uId) + " " + ircv3::EncodeAttrs(mssAttrs);
    }

    void SendNetworkList(CClient* pClient, CUser* pUser) {
        bool bBatch = pClient->HasBatch();
        CString sRef = "bn" + ircv3::RandomId(8);
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH +" + sRef + " " + kBatchType);
        for (CIRCNetwork* pNet : pUser->GetNetworks()) {
            CString sLine = NetworkLine(IdOf(pNet), Attrs(pNet));
            if (bBatch) sLine = "@batch=" + sRef + " " + sLine;
            pClient->PutClient(sLine);
        }
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH -" + sRef);
    }

    void NotifyAll(CUser* pUser, const CString& sLine) {
        for (CClient* pClient : pUser->GetAllClients())
            if (m_Caps.Has(pClient, kCapNotify)) pClient->PutClient(sLine);
    }

    void NotifyChange(CIRCNetwork* pNet, const MCString& mssChanged) {
        NotifyAll(pNet->GetUser(), NetworkLine(IdOf(pNet), mssChanged));
    }

    // ---- ADDNETWORK / CHANGENETWORK / DELNETWORK -----------------------

    static bool ValidPort(const CString& s, unsigned short& uPort) {
        if (s.empty() || s.find_first_not_of("0123456789") != CString::npos) return false;
        unsigned long u = s.ToULong();
        if (u < 1 || u > 65535) return false;
        uPort = (unsigned short)u;
        return true;
    }

    struct Parsed {
        CString sName, sHost, sPass, sNick, sIdent, sRealName;
        unsigned short uPort = 0;
        bool bTLS = true;
        bool bName = false, bServer = false, bNick = false, bIdent = false, bRealName = false, bPass = false;
    };

    // Validate attributes against pNet (nullptr for ADDNETWORK, where the
    // network does not exist yet). Sends a FAIL and returns false on error.
    bool ValidateAttrs(CClient* pClient, CUser* pUser, CIRCNetwork* pNet, const MCString& mssAttrs,
                       const CString& sSub, const CString& sCtx, Parsed& out) {
        static const std::set<CString> ssKnown = {"name", "state", "host", "port", "tls",
                                                  "nickname", "username", "realname", "pass", "error"};
        for (const auto& kv : mssAttrs) {
            if (!ssKnown.count(kv.first)) {
                PutFail(pClient, "BOUNCER", "UNKNOWN_ATTRIBUTE", {sSub, sCtx, kv.first}, "Unknown attribute");
                return false;
            }
            if (kv.first == "state" || kv.first == "error") {
                PutFail(pClient, "BOUNCER", "READ_ONLY_ATTRIBUTE", {sSub, sCtx, kv.first}, "Attribute is read-only");
                return false;
            }
        }
        auto get = [&](const char* k) { auto it = mssAttrs.find(k); return it == mssAttrs.end() ? nullptr : &it->second; };
        // Start from the current server, if any.
        CServer* pOld = (pNet && !pNet->GetServers().empty()) ? pNet->GetServers()[0] : nullptr;
        if (pOld) {
            out.sHost = pOld->GetName();
            out.uPort = pOld->GetPort();
            out.bTLS = pOld->IsSSL();
            out.sPass = pOld->GetPass();
        }
        out.bServer = get("host") || get("port") || get("tls") || get("pass");
        if (const CString* v = get("host")) {
            if (v->empty() || v->find_first_of(" \r\n") != CString::npos) {
                PutFail(pClient, "BOUNCER", "INVALID_ATTRIBUTE", {sSub, sCtx, "host"}, "Invalid host");
                return false;
            }
            out.sHost = *v;
        }
        if (const CString* v = get("tls")) {
            if (*v != "0" && *v != "1") {
                PutFail(pClient, "BOUNCER", "INVALID_ATTRIBUTE", {sSub, sCtx, "tls"}, "tls must be 0 or 1");
                return false;
            }
            out.bTLS = *v == "1";
            if (!get("port") && !pOld) out.uPort = 0;
        }
        if (const CString* v = get("port")) {
            if (!ValidPort(*v, out.uPort)) {
                PutFail(pClient, "BOUNCER", "INVALID_ATTRIBUTE", {sSub, sCtx, "port"}, "Invalid port");
                return false;
            }
        }
        if (out.uPort == 0) out.uPort = out.bTLS ? 6697 : 6667;
        if (const CString* v = get("pass")) { out.sPass = *v; out.bPass = true; }
        if (const CString* v = get("name")) {
            bool bSame = pNet && pNet->GetName() == *v;
            if (!CIRCNetwork::IsValidNetwork(*v) || (!bSame && pUser->FindNetwork(*v))) {
                PutFail(pClient, "BOUNCER", "INVALID_ATTRIBUTE", {sSub, sCtx, "name"},
                        "Invalid or duplicate network name");
                return false;
            }
            out.sName = *v;
            out.bName = !bSame;
        }
        if (const CString* v = get("nickname")) { out.sNick = *v; out.bNick = true; }
        if (const CString* v = get("username")) { out.sIdent = *v; out.bIdent = true; }
        if (const CString* v = get("realname")) { out.sRealName = *v; out.bRealName = true; }
        return true;
    }

    // Apply validated attributes; returns the changed attributes for notify.
    MCString ApplyAttrs(CIRCNetwork* pNet, const Parsed& in, bool bReconnect) {
        MCString mssChanged;
        if (in.bName) {
            pNet->SetName(in.sName);
            SaveIds(pNet->GetUser());
            mssChanged["name"] = in.sName;
        }
        if (in.bServer) {
            if (!pNet->GetServers().empty()) pNet->DelServer(*pNet->GetServers()[0]);
            pNet->AddServer(in.sHost, in.uPort, in.sPass, in.bTLS);
            mssChanged["host"] = in.sHost;
            mssChanged["port"] = CString(in.uPort);
            mssChanged["tls"] = in.bTLS ? "1" : "0";
            if (bReconnect && pNet->GetIRCSock())
                pNet->GetIRCSock()->Quit("Reconnecting to apply new server settings");
        }
        if (in.bNick) { pNet->SetNick(in.sNick); mssChanged["nickname"] = in.sNick; }
        if (in.bIdent) { pNet->SetIdent(in.sIdent); mssChanged["username"] = in.sIdent; }
        if (in.bRealName) { pNet->SetRealName(in.sRealName); mssChanged["realname"] = in.sRealName; }
        CZNC::Get().WriteConfig();
        return mssChanged;
    }

    void AddNetwork(CClient* pClient, CUser* pUser, const CString& sAttrs) {
        MCString mssAttrs = ircv3::DecodeAttrs(sAttrs);
        if (!mssAttrs.count("host") || mssAttrs["host"].empty()) {
            PutFail(pClient, "BOUNCER", "NEED_ATTRIBUTE", {"ADDNETWORK", "*", "host"},
                    "Missing required attribute");
            return;
        }
        if (!pUser->HasSpaceForNewNetwork()) {
            PutFail(pClient, "BOUNCER", "TOO_MANY_NETWORKS", {"ADDNETWORK", "*"}, "Network limit reached");
            return;
        }
        // Name: given, or derived from the host and made valid and unique.
        if (!mssAttrs.count("name")) {
            CString sClean;
            for (char c : mssAttrs["host"]) sClean += (isalnum((unsigned char)c) || c == '-' || c == '_') ? c : '_';
            CString sName = sClean.empty() ? "network" : sClean, sBase = sName;
            for (int i = 2; pUser->FindNetwork(sName); i++) sName = sBase + CString(i);
            mssAttrs["name"] = sName;
        }
        Parsed in;
        if (!ValidateAttrs(pClient, pUser, nullptr, mssAttrs, "ADDNETWORK", "*", in)) return;
        CString sError;
        CIRCNetwork* pNet = pUser->AddNetwork(in.sName, sError);
        if (!pNet) {
            PutFail(pClient, "BOUNCER", "INVALID_ATTRIBUTE", {"ADDNETWORK", "*", "name"}, sError);
            return;
        }
        in.bName = false;  // already named
        ApplyAttrs(pNet, in, false);
        unsigned uId = IdOf(pNet);
        pClient->PutClient(":irc.znc.in BOUNCER ADDNETWORK " + CString(uId));
        NotifyAll(pUser, NetworkLine(uId, Attrs(pNet)));
        pNet->SetIRCConnectEnabled(true);
    }

    void ChangeNetwork(CClient* pClient, CUser* pUser, const CString& sId, const CString& sAttrs) {
        CIRCNetwork* pNet = FindById(pUser, sId.ToUInt());
        if (!pNet) {
            PutFail(pClient, "BOUNCER", "INVALID_NETID", {"CHANGENETWORK", sId.empty() ? "*" : sId},
                    "Unknown network id");
            return;
        }
        MCString mssAttrs = ircv3::DecodeAttrs(sAttrs);
        if (mssAttrs.empty()) {
            PutFail(pClient, "BOUNCER", "NEED_ATTRIBUTE", {"CHANGENETWORK", sId}, "No attributes given");
            return;
        }
        Parsed in;
        if (!ValidateAttrs(pClient, pUser, pNet, mssAttrs, "CHANGENETWORK", sId, in)) return;
        MCString mssChanged = ApplyAttrs(pNet, in, true);
        pClient->PutClient(":irc.znc.in BOUNCER CHANGENETWORK " + sId);
        if (!mssChanged.empty()) NotifyChange(pNet, mssChanged);
    }

    void DelNetwork(CClient* pClient, CUser* pUser, const CString& sId) {
        CIRCNetwork* pNet = FindById(pUser, sId.ToUInt());
        if (!pNet) {
            PutFail(pClient, "BOUNCER", "INVALID_NETID", {"DELNETWORK", sId.empty() ? "*" : sId},
                    "Unknown network id");
            return;
        }
        pClient->PutClient(":irc.znc.in BOUNCER DELNETWORK " + sId);
        pUser->DeleteNetwork(pNet->GetName());  // OnDeleteNetwork notifies
        CZNC::Get().WriteConfig();
    }

    CapTracker m_Caps;
    ircv3::ISupportBurst m_Burst{{"BOUNCER_NETID"}};
    ircv3::ClientMap<ClientState> m_mClients;
    std::map<CIRCNetwork*, unsigned> m_mIds;
    std::map<CIRCNetwork*, CString> m_mErrors;
    unsigned m_uNext = 1;
};

template <>
void TModInfo<CBouncerNetworks>(CModInfo& Info) {
    Info.SetWikiPage("bouncernetworks");
    Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CBouncerNetworks,
                 "soju.im/bouncer-networks: list, bind, add, change and delete "
                 "networks from IRCv3 clients")
