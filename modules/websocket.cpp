/*
 * websocket — IRC over WebSocket (https://ircv3.net/specs/extensions/websocket)
 *
 * Global module with its own listener. Browser clients (gamja, kiwiirc, The
 * Lounge in bouncer mode) connect to ws[s]://host:port/<path>; every text
 * frame is one IRC line, every IRC line ZNC sends is one text frame.
 *
 * The WebSocket connection is bridged into a regular CClient through a
 * socketpair, so the IRC side is stock ZNC and every other module sees the
 * client as usual. The real peer address is logged at handshake time since
 * CClient::GetRemoteIP() reports the socketpair.
 *
 * Args: port=<n> [host=<bind address>] [ssl] [path=/socket]
 *       [origins=https://a.example,https://b.example] [trustedproxy=ip,ip]
 *       [maxframe=<bytes, default 65536>]
 */
#include <znc/Modules.h>
#include <znc/Client.h>
#include <znc/Socket.h>
#include <znc/znc.h>

#include <openssl/sha.h>
#include <sys/socket.h>
#include <unistd.h>

#include <deque>
#include <vector>

namespace {
const char* kGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

struct Config {
    unsigned short uPort = 0;
    CString sHost;
    bool bSSL = false;
    CString sPath = "/socket";
    VCString vsOrigins;
    VCString vsTrustedProxies;
    size_t uMaxFrame = 65536;
};

CString AcceptKey(const CString& sKey) {
    CString sIn = sKey + kGuid;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)sIn.data(), sIn.size(), digest);
    return CString((const char*)digest, SHA_DIGEST_LENGTH).Base64Encode_n();
}

// Non-browser clients send no Origin; the allow-list is a browser-side
// protection, so only an actual Origin is checked.
bool OriginAllowed(const Config& cfg, const CString& sOrigin) {
    if (cfg.vsOrigins.empty() || sOrigin.empty()) return true;
    for (const CString& s : cfg.vsOrigins)
        if (sOrigin.WildCmp(s, CString::CaseInsensitive)) return true;
    return false;
}
}  // namespace

class CWebSocketMod;
class CWSConn;

// Module side of the socketpair: IRC lines from the CClient -> frames.
class CWSBridge : public CSocket {
  public:
    CWSBridge(CModule* pMod, CWSConn* pConn) : CSocket(pMod), m_pConn(pConn) { EnableReadLine(); }
    void ReadLine(const CString& sLine) override;
    void Disconnected() override;
    void Detach() { m_pConn = nullptr; }

  private:
    CWSConn* m_pConn;
};

class CWSConn : public CSocket {
  public:
    CWSConn(CModule* pMod, const Config& cfg) : CSocket(pMod), m_Cfg(cfg) {
        EnableReadLine();
        SetMaxBufferThreshold(16384);
    }
    ~CWSConn() override {
        if (m_pBridge) {
            m_pBridge->Detach();
            m_pBridge->Close();
        }
    }

    // ---- handshake (line mode) --------------------------------------
    void ReadLine(const CString& sLineIn) override {
        if (m_bUpgraded) return;
        CString sLine = sLineIn;
        sLine.TrimRight("\r\n");
        if (m_sRequestLine.empty()) {
            m_sRequestLine = sLine;
            return;
        }
        if (!sLine.empty()) {
            CString sName = sLine.Token(0, false, ":").AsLower();
            CString sValue = sLine.Token(1, true, ":");
            sValue.Trim();
            m_msHeaders[sName] = sValue;
            return;
        }
        Handshake();
    }

    void Handshake() {
        CString sMethod = m_sRequestLine.Token(0), sPath = m_sRequestLine.Token(1);
        CString sPathOnly = sPath.Token(0, false, "?");
        CString sPeer = GetRemoteIP();
        auto fwd = m_msHeaders.find("x-forwarded-for");
        if (fwd != m_msHeaders.end()) {
            for (const CString& p : m_Cfg.vsTrustedProxies)
                if (p == sPeer) { sPeer = fwd->second.Token(0, false, ","); sPeer.Trim(); break; }
        }
        if (sMethod != "GET" || sPathOnly != m_Cfg.sPath) {
            Reply("404 Not Found", "text/plain", "No WebSocket endpoint here\n");
            return;
        }
        if (!m_msHeaders["upgrade"].Equals("websocket") || !m_msHeaders["connection"].AsLower().Contains("upgrade") ||
            m_msHeaders["sec-websocket-version"] != "13" || m_msHeaders["sec-websocket-key"].empty()) {
            Reply("400 Bad Request", "text/plain", "WebSocket upgrade required (version 13)\n");
            return;
        }
        if (!OriginAllowed(m_Cfg, m_msHeaders["origin"])) {
            Reply("403 Forbidden", "text/plain", "Origin not allowed\n");
            return;
        }
        CString sProto;
        VCString vs;
        m_msHeaders["sec-websocket-protocol"].Split(",", vs, false, "", "", true, true);
        for (const CString& p : vs) if (p == "text.ircv3.net") sProto = p;
        if (sProto.empty()) for (const CString& p : vs) if (p == "binary.ircv3.net") sProto = p;

        // Bridge into a real CClient.
        int fds[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
            Reply("500 Internal Server Error", "text/plain", "socketpair failed\n");
            return;
        }
        CClient* pClient = new CClient();
        pClient->ConnectFD(fds[0], fds[0], "WS::" + sPeer);
        CZNC::Get().GetManager().AddSock(pClient, "WS::" + sPeer);
        m_pBridge = new CWSBridge(GetModule(), this);
        m_pBridge->ConnectFD(fds[1], fds[1], "WSBridge::" + sPeer);
        // AddSocket() only tracks the socket for module unload; the manager
        // must own it too or it never gets polled.
        CZNC::Get().GetManager().AddSock(m_pBridge, "WSBridge::" + sPeer);
        GetModule()->AddSocket(m_pBridge);

        CString sResp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: " + AcceptKey(m_msHeaders["sec-websocket-key"]) + "\r\n";
        if (!sProto.empty()) sResp += "Sec-WebSocket-Protocol: " + sProto + "\r\n";
        sResp += "\r\n";
        Write(sResp);
        m_bUpgraded = true;
        m_bBinary = sProto == "binary.ircv3.net";
        DisableReadLine();
        GetModule()->PutModule("WebSocket client from " + sPeer + " (" + (sProto.empty() ? "no subprotocol" : sProto) + ")");
    }

    void Reply(const CString& sStatus, const CString& sType, const CString& sBody) {
        Write("HTTP/1.1 " + sStatus + "\r\nContent-Type: " + sType + "\r\nContent-Length: " + CString(sBody.size()) +
              "\r\nConnection: close\r\n\r\n" + sBody);
        Close(Csock::CLT_AFTERWRITE);
    }

    // ---- frames (raw mode) ------------------------------------------
    void ReadData(const char* data, size_t len) override {
        if (!m_bUpgraded) return;
        m_sIn.append(data, len);
        while (ParseFrame()) {}
    }

    bool ParseFrame() {
        if (m_sIn.size() < 2) return false;
        const unsigned char* p = (const unsigned char*)m_sIn.data();
        bool bFin = p[0] & 0x80;
        unsigned uOp = p[0] & 0x0F;
        bool bMask = p[1] & 0x80;
        size_t uLen = p[1] & 0x7F, uHdr = 2;
        if (uLen == 126) {
            if (m_sIn.size() < 4) return false;
            uLen = (p[2] << 8) | p[3];
            uHdr = 4;
        } else if (uLen == 127) {
            if (m_sIn.size() < 10) return false;
            uLen = 0;
            for (int i = 2; i < 10; i++) uLen = (uLen << 8) | p[i];
            uHdr = 10;
        }
        if (!bMask) { Fail(1002, "Client frames must be masked"); return false; }
        if (uLen > m_Cfg.uMaxFrame) { Fail(1009, "Frame too large"); return false; }
        if (m_sIn.size() < uHdr + 4 + uLen) return false;
        unsigned char key[4];
        memcpy(key, p + uHdr, 4);
        CString sPayload(m_sIn.data() + uHdr + 4, uLen);
        for (size_t i = 0; i < uLen; i++) sPayload[i] ^= key[i & 3];
        m_sIn.erase(0, uHdr + 4 + uLen);

        switch (uOp) {
            case 0x0:  // continuation
                if (m_uFragOp == 0) { Fail(1002, "Unexpected continuation"); return false; }
                m_sFrag += sPayload;
                if (m_sFrag.size() > m_Cfg.uMaxFrame) { Fail(1009, "Message too large"); return false; }
                if (bFin) { OnMessage(m_uFragOp, m_sFrag); m_sFrag.clear(); m_uFragOp = 0; }
                break;
            case 0x1: case 0x2:
                if (m_uFragOp != 0) { Fail(1002, "Interleaved fragments"); return false; }
                if (bFin) OnMessage(uOp, sPayload);
                else { m_uFragOp = uOp; m_sFrag = sPayload; }
                break;
            case 0x8:
                SendFrame(0x8, sPayload.substr(0, 2));
                Close(Csock::CLT_AFTERWRITE);
                return false;
            case 0x9:
                SendFrame(0xA, sPayload);
                break;
            case 0xA:
                break;
            default:
                Fail(1002, "Unknown opcode");
                return false;
        }
        return true;
    }

    void OnMessage(unsigned uOp, const CString& sData) {
        if (!m_pBridge) return;
        // One IRC line per message, but tolerate CRLF-separated bundles.
        VCString vs;
        sData.Split("\n", vs, false);
        for (CString s : vs) {
            s.TrimRight("\r");
            if (!s.empty()) m_pBridge->Write(s + "\r\n");
        }
    }

    void SendText(const CString& sLine) { SendFrame(m_bBinary ? 0x2 : 0x1, sLine); }

    void SendFrame(unsigned uOp, const CString& sPayload) {
        CString sFrame;
        sFrame += (char)(0x80 | uOp);
        size_t n = sPayload.size();
        if (n < 126) sFrame += (char)n;
        else if (n < 65536) { sFrame += (char)126; sFrame += (char)(n >> 8); sFrame += (char)(n & 0xFF); }
        else { sFrame += (char)127; for (int i = 7; i >= 0; i--) sFrame += (char)((n >> (8 * i)) & 0xFF); }
        sFrame += sPayload;
        Write(sFrame);
    }

    void Fail(unsigned short uCode, const CString& sReason) {
        CString sPayload;
        sPayload += (char)(uCode >> 8);
        sPayload += (char)(uCode & 0xFF);
        SendFrame(0x8, sPayload + sReason);
        Close(Csock::CLT_AFTERWRITE);
    }

    void Disconnected() override {
        if (m_pBridge) {
            m_pBridge->Detach();
            m_pBridge->Close();
            m_pBridge = nullptr;
        }
    }

    void BridgeGone() { m_pBridge = nullptr; Close(Csock::CLT_AFTERWRITE); }

  private:
    Config m_Cfg;
    CString m_sRequestLine;
    MCString m_msHeaders;
    bool m_bUpgraded = false;
    bool m_bBinary = false;
    CString m_sIn, m_sFrag;
    unsigned m_uFragOp = 0;
    CWSBridge* m_pBridge = nullptr;
};

void CWSBridge::ReadLine(const CString& sLine) {
    CString s = sLine;
    s.TrimRight("\r\n");
    if (m_pConn) m_pConn->SendText(s);
}

void CWSBridge::Disconnected() {
    if (m_pConn) m_pConn->BridgeGone();
    m_pConn = nullptr;
}

class CWSListener : public CSocket {
  public:
    CWSListener(CModule* pMod, const Config& cfg) : CSocket(pMod), m_Cfg(cfg) {}
    Csock* GetSockObj(const CString& sHost, unsigned short uPort) override {
        CWSConn* p = new CWSConn(GetModule(), m_Cfg);
        p->SetSockName("WS::conn::" + sHost);
        return p;
    }

  private:
    Config m_Cfg;
};

class CWebSocketMod : public CModule {
  public:
    MODCONSTRUCTOR(CWebSocketMod) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "websocket must be loaded as a global module";
            return false;
        }
        VCString vs;
        sArgs.Split(" ", vs, false);
        for (const CString& a : vs) {
            if (a.StartsWith("port=")) m_Cfg.uPort = CString(a.substr(5)).ToUShort();
            else if (a.StartsWith("host=")) m_Cfg.sHost = a.substr(5);
            else if (a == "ssl") m_Cfg.bSSL = true;
            else if (a.StartsWith("path=")) m_Cfg.sPath = a.substr(5);
            else if (a.StartsWith("origins=")) CString(a.substr(8)).Split(",", m_Cfg.vsOrigins, false);
            else if (a.StartsWith("trustedproxy=")) CString(a.substr(13)).Split(",", m_Cfg.vsTrustedProxies, false);
            else if (a.StartsWith("maxframe=")) m_Cfg.uMaxFrame = CString(a.substr(9)).ToULong();
            else { sMessage = "Unknown argument " + a; return false; }
        }
        if (m_Cfg.uPort == 0) { sMessage = "port=<n> is required"; return false; }
        if (!m_Cfg.sPath.StartsWith("/")) m_Cfg.sPath = "/" + m_Cfg.sPath;
        CWSListener* pListener = new CWSListener(this, m_Cfg);
        pListener->SetSockName("WS::listener");
        if (!GetManager()->ListenHost(m_Cfg.uPort, "WS::listener", m_Cfg.sHost, m_Cfg.bSSL, SOMAXCONN, pListener)) {
            sMessage = "Cannot listen on port " + CString(m_Cfg.uPort);
            delete pListener;
            return false;
        }
        AddSocket(pListener);
        sMessage = "Listening for WebSocket clients on " + (m_Cfg.sHost.empty() ? CString("*") : m_Cfg.sHost) + ":" +
                   CString(m_Cfg.uPort) + m_Cfg.sPath + (m_Cfg.bSSL ? " (TLS)" : "");
        return true;
    }

    void OnModCommand(const CString& sCommand) override {
        PutModule("WebSocket listener on port " + CString(m_Cfg.uPort) + ", path " + m_Cfg.sPath);
    }

  private:
    Config m_Cfg;
};

template <>
void TModInfo<CWebSocketMod>(CModInfo& Info) {
    Info.SetWikiPage("websocket");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("port=<n> [host=<bind>] [ssl] [path=/socket] [origins=a,b] [trustedproxy=ip,ip]");
}

GLOBALMODULEDEFS(CWebSocketMod, "IRC over WebSocket listener for browser clients")
