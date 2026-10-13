/*
 * webpush — soju.im/webpush for ZNC: Web Push notifications (RFC 8030,
 * RFC 8291 aes128gcm encryption, RFC 8292 VAPID) for highlights and private
 * messages while the user has no active client.
 *
 * Global module.
 *   cap      soju.im/webpush
 *   ISUPPORT VAPID=<urlsafe-base64 P-256 public key>
 *   commands WEBPUSH REGISTER <endpoint> <keys>   keys: p256dh=...;auth=...
 *            WEBPUSH UNREGISTER <endpoint>
 *   replies  WEBPUSH REGISTER <endpoint> / WEBPUSH UNREGISTER <endpoint>
 *            FAIL WEBPUSH INVALID_PARAMS|INTERNAL_ERROR <command> <endpoint> :msg
 *
 * A push is sent for a PRIVMSG/NOTICE to the user (query) or a channel line
 * containing the user's nick. It goes out at once when no client is
 * present on that network (none attached, or all of them away via AWAY or
 * draft/pre-away). Otherwise soju's rule applies: the push is delayed by a
 * short grace period and dropped if a read marker (readmarker module)
 * shows the message was read meanwhile, so a client that is open in the
 * background does not silence every other device. Each push carries one
 * IRC line (tags time and msgid kept). Endpoints answering 404 or 410 are
 * dropped.
 *
 * Storage (module NV): "vapid" -> private key (DER, base64);
 *   "sub:<user>:<network>:<endpoint>" -> p256dh=...;auth=...
 *   (<network> is empty for a subscription made on an unbound connection)
 *
 * Args: [ttl=<seconds, default 86400>] [always] [contact=<mailto: or https: URI>]
 *   always: push even with clients present; contact: VAPID "sub" claim,
 *   which push services may use to reach the operator.
 * Commands: list, test, always on|off (runtime toggle, persisted),
 *           rules, rule add|del <kind> <value>, rule clear [kind]
 *
 * Push rules (vendor cap solder.chat/webpush-rules, docs/webpush-rules.md):
 * per-user highlight/mute/all/ignore rules decide which messages are
 * pushed, managed over IRC with WEBPUSH RULES / WEBPUSH RULE ADD|DEL|CLEAR.
 * Rules set on a connection bound to a network apply to that network,
 * rules set on an unbound connection apply to every network; the
 * effective set is the union. Decision order for each PRIVMSG, NOTICE,
 * ACTION or INVITE: ignored sender -> drop; muted buffer -> drop; private
 * message or INVITE -> push; "all" buffer -> push; channel line matching
 * the nick (whole word) or a highlight rule -> push; otherwise drop.
 * Storage: "rule:<user>:<network>:<kind>:<value>" (network empty for
 * account-wide).
 *
 * Subscriptions are scoped by network and endpoint, as in soju. For an
 * event on a network, every endpoint subscribed to that network gets one
 * push; endpoints subscribed only from an unbound connection get it when
 * they have no subscription for that network.
 */
#include <znc/Modules.h>
#include <znc/Chan.h>
#include <znc/Client.h>
#include <znc/IRCNetwork.h>
#include <znc/IRCSock.h>
#include <znc/Socket.h>
#include <znc/Utils.h>
#include <znc/User.h>
#include <znc/znc.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "caps.h"
#include "ids.h"
#include "isupport.h"
#include "msgtag.h"
#include "replies.h"

#include <ctime>
#include <map>
#include <memory>
#include <cstring>
#include <regex>
#include <unistd.h>

using ircv3::CapTracker;
using ircv3::PutFail;

namespace {
const char* kCap = "soju.im/webpush";
const char* kCapRules = "solder.chat/webpush-rules";
const char* kRulesBatch = "solder.chat/webpush-rules";
const char* kCmd = "WEBPUSH";
const unsigned kGraceSeconds = 5;  // like soju: time for a present client to read it
const size_t kMaxRulesPerScope = 100;
const size_t kMaxRuleValue = 200;
const size_t kMaxMatchInput = 4096;  // bytes of text handed to a regex

bool ValidKind(const CString& s) {
    return s == "highlight" || s == "mute" || s == "all" || s == "ignore";
}

// IRC casemapping fold for buffer names.
CString FoldName(const CString& sName, const CString& sMapping) {
    CString out = sName.AsLower();
    if (sMapping != "ascii") {
        for (char& c : out) {
            if (c == '[') c = '{';
            else if (c == ']') c = '}';
            else if (c == '\\') c = '|';
            else if (c == '~' && sMapping == "rfc1459") c = '^';
        }
    }
    return out;
}

bool IsWordChar(unsigned char c) { return isalnum(c) || c == '_'; }

// Case-insensitive whole-word occurrence of sWord in sText (both lowered).
bool WordMatch(const CString& sTextLower, const CString& sWordLower) {
    if (sWordLower.empty()) return false;
    for (size_t uPos = sTextLower.find(sWordLower); uPos != CString::npos;
         uPos = sTextLower.find(sWordLower, uPos + 1)) {
        bool bLeft = uPos == 0 || !IsWordChar(sTextLower[uPos - 1]);
        size_t uEnd = uPos + sWordLower.size();
        bool bRight = uEnd >= sTextLower.size() || !IsWordChar(sTextLower[uEnd]);
        if (bLeft && bRight) return true;
    }
    return false;
}

struct Rule {
    CString sKind, sValue;
    bool bRegex = false;
    std::regex re;

    // "/.../" is an ECMAScript regex, anything else a whole-word pattern.
    bool Compile(CString& sError) {
        if (sValue.size() >= 2 && sValue.front() == '/' && sValue.back() == '/') {
            try {
                re = std::regex(sValue.substr(1, sValue.size() - 2), std::regex::ECMAScript | std::regex::icase);
                bRegex = true;
            } catch (const std::regex_error& e) {
                sError = CString("Bad regular expression: ") + e.what();
                return false;
            }
        }
        return true;
    }
    bool MatchesText(const CString& sText) const {
        if (bRegex) {
            CString sIn = sText.size() > kMaxMatchInput ? CString(sText.substr(0, kMaxMatchInput)) : sText;
            try { return std::regex_search(sIn, re); } catch (const std::regex_error&) { return false; }
        }
        return WordMatch(sText.AsLower(), sValue.AsLower());
    }
    // ignore: nick!user@host mask, or a bare nick pattern.
    bool MatchesSender(const CNick& Sender) const {
        if (sValue.Contains("!") || sValue.Contains("@"))
            return Sender.GetNickMask().WildCmp(sValue, CString::CaseInsensitive);
        return Sender.GetNick().WildCmp(sValue, CString::CaseInsensitive);
    }
};

// ---- small crypto helpers (OpenSSL 1.1 / 3 compatible API subset) ----------

CString B64Url(const CString& s) {
    CString out = s.Base64Encode_n();
    out.Replace("+", "-");
    out.Replace("/", "_");
    while (!out.empty() && out.back() == '=') out.pop_back();
    out.Replace("\n", "");
    return out;
}

CString B64UrlDecode(CString s) {
    s.Replace("-", "+");
    s.Replace("_", "/");
    while (s.size() % 4) s += "=";
    return s.Base64Decode_n();
}

CString Hkdf(const CString& sSalt, const CString& sIkm, const CString& sInfo, size_t uLen) {
    CString out(uLen, '\0');
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    size_t n = uLen;
    bool ok = ctx && EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_salt(ctx, (const unsigned char*)sSalt.data(), (int)sSalt.size()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, (const unsigned char*)sIkm.data(), (int)sIkm.size()) > 0 &&
              EVP_PKEY_CTX_add1_hkdf_info(ctx, (const unsigned char*)sInfo.data(), (int)sInfo.size()) > 0 &&
              EVP_PKEY_derive(ctx, (unsigned char*)&out[0], &n) > 0;
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return ok ? out : CString();
}

struct ECKey {
    EC_KEY* key = nullptr;
    ~ECKey() { if (key) EC_KEY_free(key); }
};

bool GenerateP256(ECKey& k) {
    k.key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    return k.key && EC_KEY_generate_key(k.key) == 1;
}

// 65-byte uncompressed point.
CString PublicRaw(const EC_KEY* key) {
    const EC_GROUP* g = EC_KEY_get0_group(key);
    size_t n = EC_POINT_point2oct(g, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    CString out(n, '\0');
    EC_POINT_point2oct(g, EC_KEY_get0_public_key(key), POINT_CONVERSION_UNCOMPRESSED, (unsigned char*)&out[0], n, nullptr);
    return out;
}

CString PrivateDer(const EC_KEY* key) {
    int n = i2d_ECPrivateKey(const_cast<EC_KEY*>(key), nullptr);
    if (n <= 0) return "";
    CString out(n, '\0');
    unsigned char* p = (unsigned char*)&out[0];
    i2d_ECPrivateKey(const_cast<EC_KEY*>(key), &p);
    return out;
}

bool PrivateFromDer(ECKey& k, const CString& sDer) {
    const unsigned char* p = (const unsigned char*)sDer.data();
    k.key = d2i_ECPrivateKey(nullptr, &p, (long)sDer.size());
    return k.key != nullptr;
}

bool PointFromRaw(const EC_GROUP* g, const CString& sRaw, EC_POINT** ppOut) {
    *ppOut = EC_POINT_new(g);
    return EC_POINT_oct2point(g, *ppOut, (const unsigned char*)sRaw.data(), sRaw.size(), nullptr) == 1;
}

// ECDSA P-256 signature as raw r||s (64 bytes).
CString SignES256(const EC_KEY* key, const CString& sData) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)sData.data(), sData.size(), digest);
    ECDSA_SIG* sig = ECDSA_do_sign(digest, sizeof digest, const_cast<EC_KEY*>(key));
    if (!sig) return "";
    const BIGNUM *r, *s;
    ECDSA_SIG_get0(sig, &r, &s);
    CString out(64, '\0');
    BN_bn2binpad(r, (unsigned char*)&out[0], 32);
    BN_bn2binpad(s, (unsigned char*)&out[32], 32);
    ECDSA_SIG_free(sig);
    return out;
}

// RFC 8291 aes128gcm, single record. Returns the body or "" on failure.
CString EncryptAes128Gcm(const CString& sPlain, const CString& sClientPubRaw, const CString& sAuth) {
    ECKey eph;
    if (!GenerateP256(eph)) return "";
    const EC_GROUP* g = EC_KEY_get0_group(eph.key);
    EC_POINT* pClient = nullptr;
    if (!PointFromRaw(g, sClientPubRaw, &pClient)) { if (pClient) EC_POINT_free(pClient); return ""; }
    CString sSecret(32, '\0');
    int n = ECDH_compute_key(&sSecret[0], 32, pClient, eph.key, nullptr);
    EC_POINT_free(pClient);
    if (n != 32) return "";
    CString sServerPub = PublicRaw(eph.key);
    CString sIkm = Hkdf(sAuth, sSecret, CString("WebPush: info\0", 14) + sClientPubRaw + sServerPub, 32);
    CString sSalt(16, '\0');
    RAND_bytes((unsigned char*)&sSalt[0], 16);
    CString sCek = Hkdf(sSalt, sIkm, CString("Content-Encoding: aes128gcm\0", 28), 16);
    CString sNonce = Hkdf(sSalt, sIkm, CString("Content-Encoding: nonce\0", 24), 12);
    if (sIkm.empty() || sCek.empty() || sNonce.empty()) return "";

    CString sPadded = sPlain + CString("\x02", 1);  // last record delimiter
    CString sCipher(sPadded.size() + 16, '\0');
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0, total = 0;
    bool ok = ctx && EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, (const unsigned char*)sCek.data(), (const unsigned char*)sNonce.data()) == 1 &&
              EVP_EncryptUpdate(ctx, (unsigned char*)&sCipher[0], &len, (const unsigned char*)sPadded.data(), (int)sPadded.size()) == 1;
    total = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, (unsigned char*)&sCipher[total], &len) == 1;
    total += len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, &sCipher[total]) == 1;
    total += 16;
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (!ok) return "";
    sCipher.resize(total);

    // RFC 8291 allows any record size, but goguma requires the field to
    // equal the total payload length (one record covering everything).
    uint32_t rs = (uint32_t)(16 + 4 + 1 + sServerPub.size() + sCipher.size());
    CString sHeader = sSalt;
    sHeader += (char)(rs >> 24); sHeader += (char)(rs >> 16); sHeader += (char)(rs >> 8); sHeader += (char)rs;
    sHeader += (char)sServerPub.size();
    sHeader += sServerPub;
    return sHeader + sCipher;
}

struct Url {
    bool bTLS = false;
    CString sHost, sPath, sOrigin;
    unsigned short uPort = 0;
};

bool ParseUrl(const CString& sUrl, Url& u) {
    CString s = sUrl;
    if (s.TrimPrefix("https://")) u.bTLS = true;
    else if (s.TrimPrefix("http://")) u.bTLS = false;
    else return false;
    CString sHostPort = s.Token(0, false, "/");
    u.sPath = "/" + s.Token(1, true, "/");
    u.sHost = sHostPort.Token(0, false, ":");
    CString sPort = sHostPort.Token(1, false, ":");
    u.uPort = sPort.empty() ? (u.bTLS ? 443 : 80) : sPort.ToUShort();
    u.sOrigin = (u.bTLS ? "https://" : "http://") + sHostPort;
    return !u.sHost.empty() && u.uPort != 0;
}
}  // namespace

class CWebPush;

// One HTTP POST to a push service.
class CPushRequest : public CSocket {
  public:
    CPushRequest(CModule* pMod, const CString& sSubKey, const Url& url, const CString& sRequest)
        : CSocket(pMod), m_sSubKey(sSubKey), m_sHost(url.sHost), m_sRequest(sRequest) {
        EnableReadLine();
        SetTimeout(30);
    }
    void Connected() override { Write(m_sRequest); }
    void ReadLine(const CString& sLine) override {
        if (m_sStatus.empty()) {
            m_sStatus = sLine.Token(1);
            DEBUG("webpush: " << m_sHost << " answered " << m_sStatus);
            if (m_sStatus == "404" || m_sStatus == "410") m_bGone = true;
            Close(Csock::CLT_AFTERWRITE);
        }
    }
    void Disconnected() override;
    void Timeout() override { DEBUG("webpush: timeout talking to " << m_sHost); }

  private:
    CString m_sSubKey, m_sHost, m_sRequest, m_sStatus;
    bool m_bGone = false;
    friend class CWebPush;
};

// A push waiting out the grace period.
class CPendingPush : public CTimer {
  public:
    CPendingPush(CModule* pMod, CString sUser, CString sNet, CString sTarget, CString sTime, CString sLine)
        // Timer labels must be unique per module: AddTimer refuses a
        // duplicate, which would drop every push after the first.
        : CTimer(pMod, kGraceSeconds, 1, "webpush-pending-" + CString(++s_uSeq), "Push unless the message gets read first"),
          m_sUser(std::move(sUser)), m_sNet(std::move(sNet)), m_sTarget(std::move(sTarget)),
          m_sTime(std::move(sTime)), m_sLine(std::move(sLine)) {}

  protected:
    void RunJob() override;

  private:
    static unsigned long long s_uSeq;
    CString m_sUser, m_sNet, m_sTarget, m_sTime, m_sLine;
    friend class CWebPush;
};
unsigned long long CPendingPush::s_uSeq = 0;

class CWebPush : public CModule {
  public:
    MODCONSTRUCTOR(CWebPush) {}

    bool OnLoad(const CString& sArgs, CString& sMessage) override {
        if (GetType() != CModInfo::GlobalModule) {
            sMessage = "webpush must be loaded as a global module";
            return false;
        }
        VCString vs;
        sArgs.Split(" ", vs, false);
        for (const CString& a : vs) {
            if (a.StartsWith("ttl=")) m_uTTL = CString(a.substr(4)).ToUInt();
            else if (a == "always") m_bAlways = true;
            else if (a.StartsWith("contact=")) m_sContact = a.substr(8);
            else { sMessage = "Unknown argument " + a; return false; }
        }
        if (m_sContact.empty()) {
            char host[256] = "localhost";
            if (gethostname(host, sizeof host) != 0) strcpy(host, "localhost");
            host[sizeof host - 1] = '\0';
            m_sContact = CString("mailto:znc@") + host;
        }
        if (!m_sContact.StartsWith("mailto:") && !m_sContact.StartsWith("https://")) {
            sMessage = "contact= must be a mailto: or https: URI";
            return false;
        }
        if (GetNV("always") == "1") m_bAlways = true;
        MigrateSubscriptions();
        LoadRules();
        CString sDer = GetNV("vapid").Base64Decode_n();
        if (sDer.empty() || !PrivateFromDer(m_Vapid, sDer)) {
            if (!GenerateP256(m_Vapid)) { sMessage = "Cannot generate VAPID key"; return false; }
            SetNV("vapid", PrivateDer(m_Vapid.key).Base64Encode_n());
        }
        m_sVapidPub = B64Url(PublicRaw(m_Vapid.key));
        sMessage = "VAPID public key " + m_sVapidPub;
        return true;
    }

    // ---- caps / ISUPPORT -----------------------------------------------

    void OnClientCapLs(CClient* pClient, SCString& ssCaps) override {
        ssCaps.insert(kCap);
        ssCaps.insert(kCapRules);
    }
    bool IsClientCapSupported(CClient* pClient, const CString& sCap, bool bState) override {
        return sCap.Equals(kCap) || sCap.Equals(kCapRules);
    }
    void OnClientCapRequest(CClient* pClient, const CString& sCap, bool bState) override {
        if (sCap.Equals(kCap) || sCap.Equals(kCapRules)) m_Caps.Set(pClient, sCap, bState);
    }
    void OnClientDisconnect() override {
        m_Caps.Forget(GetClient());
        m_Burst.Forget(GetClient());
    }
    MCString ISupportFor(CClient* pClient) {
        if (!m_Caps.Has(pClient, kCap)) return {};
        return {{"VAPID", m_sVapidPub}};
    }
    // VAPID goes inside the registration burst; an upstream VAPID token is
    // dropped because WEBPUSH is answered here.
    EModRet OnSendToClientMessage(CMessage& Message) override {
        return m_Burst.OnSend(Message, [this](CClient* p) { return ISupportFor(p); });
    }
    void OnClientAttached() override {
        m_Burst.OnAttached(GetClient(), [this](CClient* p) { return ISupportFor(p); });
    }

    // ---- WEBPUSH command -----------------------------------------------

    EModRet OnUserRawMessage(CMessage& Message) override {
        if (!Message.GetCommand().Equals(kCmd)) return CONTINUE;
        CClient* pClient = Message.GetClient() ? Message.GetClient() : GetClient();
        if (!pClient) return HALT;
        CString sSub = Message.GetParam(0).AsUpper(), sEndpoint = Message.GetParam(1);
        if (sSub == "REGISTER") {
            Url u;
            if (sEndpoint.empty() || Message.GetParam(2).empty() || Message.GetParams().size() != 3) {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"REGISTER", sEndpoint.empty() ? "*" : sEndpoint}, "REGISTER <endpoint> <keys>");
                return HALT;
            }
            if (!ParseUrl(sEndpoint, u)) {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"REGISTER", sEndpoint}, "Invalid endpoint URL");
                return HALT;
            }
            MCString keys = ircv3::DecodeAttrs(Message.GetParam(2));
            CString sP256 = B64UrlDecode(keys["p256dh"]), sAuth = B64UrlDecode(keys["auth"]);
            if (sP256.size() != 65 || sAuth.size() != 16) {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"REGISTER", sEndpoint}, "keys must carry p256dh (65 bytes) and auth (16 bytes)");
                return HALT;
            }
            MCString stored = {{"p256dh", keys["p256dh"]}, {"auth", keys["auth"]}};
            SetNV(SubKey(pClient->GetUser(), NetName(pClient), sEndpoint), ircv3::EncodeAttrs(stored));
            pClient->PutClient(":irc.znc.in WEBPUSH REGISTER " + sEndpoint);
        } else if (sSub == "UNREGISTER") {
            if (sEndpoint.empty()) {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"UNREGISTER", "*"}, "UNREGISTER <endpoint>");
                return HALT;
            }
            DelNV(SubKey(pClient->GetUser(), NetName(pClient), sEndpoint));
            pClient->PutClient(":irc.znc.in WEBPUSH UNREGISTER " + sEndpoint);
        } else if (sSub == "RULES" || sSub == "RULE") {
            if (!m_Caps.Has(pClient, kCapRules)) {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"RULE"}, CString(kCapRules) + " was not negotiated");
                return HALT;
            }
            CUser* pUser = pClient->GetUser();
            const CString sNet = NetName(pClient);
            if (sSub == "RULES") {
                SendRules(pClient, pUser, sNet);
                return HALT;
            }
            CString sAction = Message.GetParam(1).AsUpper(), sKind = Message.GetParam(2).AsLower(), sValue = Message.GetParam(3);
            CString sError;
            if (sAction == "CLEAR") {
                if (!sKind.empty() && !ValidKind(sKind)) {
                    PutFail(pClient, kCmd, "INVALID_PARAMS", {"RULE"}, "Unknown rule kind " + sKind);
                    return HALT;
                }
                ClearRules(pUser, sNet, sKind);
                pClient->PutClient(":irc.znc.in WEBPUSH RULE CLEAR" + (sKind.empty() ? "" : " " + sKind));
            } else if (sAction == "ADD" || sAction == "DEL") {
                bool bOk = sAction == "ADD" ? AddRule(pUser, sNet, sKind, sValue, sError)
                                            : DelRule(pUser, sNet, sKind, sValue, sError);
                if (!bOk) {
                    PutFail(pClient, kCmd, sError.StartsWith("Too many") ? "LIMIT_EXCEEDED" : "INVALID_PARAMS", {"RULE"}, sError);
                    return HALT;
                }
                pClient->PutClient(":irc.znc.in WEBPUSH RULE " + sAction + " " + sKind + " :" + sValue);
            } else {
                PutFail(pClient, kCmd, "INVALID_PARAMS", {"RULE"}, "RULE ADD|DEL <kind> <value> or RULE CLEAR [<kind>]");
            }
        } else {
            PutFail(pClient, kCmd, "INVALID_PARAMS", {sSub.empty() ? "*" : sSub, "*"}, "Unknown subcommand");
        }
        return HALT;
    }

    // ---- triggers ------------------------------------------------------

    EModRet OnPrivTextMessage(CTextMessage& M) override { Consider(M, true); return CONTINUE; }
    EModRet OnPrivActionMessage(CActionMessage& M) override { Consider(M, true); return CONTINUE; }
    EModRet OnPrivNoticeMessage(CNoticeMessage& M) override { Consider(M, true); return CONTINUE; }
    EModRet OnChanTextMessage(CTextMessage& M) override { Consider(M, false); return CONTINUE; }
    EModRet OnChanActionMessage(CActionMessage& M) override { Consider(M, false); return CONTINUE; }
    EModRet OnChanNoticeMessage(CNoticeMessage& M) override { Consider(M, false); return CONTINUE; }
    EModRet OnInviteMessage(CInviteMessage& M) override {
        CIRCNetwork* pNet = M.GetNetwork() ? M.GetNetwork() : GetNetwork();
        if (!pNet || !CNick(M.GetInvitedNick()).NickEquals(pNet->GetCurNick())) return CONTINUE;
        if (Decide(pNet, M.GetNick(), M.GetChannel(), true, "")) Schedule(pNet, M, M.GetChannel());
        return CONTINUE;
    }

    void OnModCommand(const CString& sCommand) override {
        CString sCmd = sCommand.Token(0);
        if (sCmd.Equals("LIST")) {
            CUser* pUser = GetUser();
            if (!pUser) { PutModule("No user context"); return; }
            const CString sPrefix = "sub:" + pUser->GetUsername() + ":";
            CTable t;
            t.AddColumn("Endpoint");
            t.AddColumn("Network");
            for (auto it = BeginNV(); it != EndNV(); ++it) {
                if (!it->first.StartsWith(sPrefix)) continue;
                CString sNet, sEndpoint;
                SplitKey(it->first.substr(sPrefix.size()), sNet, sEndpoint);
                t.AddRow();
                t.SetCell("Endpoint", sEndpoint);
                t.SetCell("Network", sNet.empty() ? "(any)" : sNet);
            }
            PutModule(t);
            PutModule("VAPID public key: " + m_sVapidPub);
            PutModule("VAPID contact: " + m_sContact);
        } else if (sCmd.Equals("TEST")) {
            CUser* pUser = GetUser();
            if (!pUser) { PutModule("No user context"); return; }
            // Looks like a private message from a user, which is what
            // clients turn into a visible notification.
            CString sLine = "@time=" + CUtils::FormatServerTime(CUtils::GetTime()) + ";msgid=znc-webpush-test-" +
                            ircv3::RandomId(8) + " :webpush!znc@znc.in PRIVMSG " + pUser->GetNick() +
                            " :Test notification from ZNC (" + CString(time(nullptr)) + ")";
            int n = PushAll(pUser, nullptr, sLine);
            PutModule("Sent " + CString(n) + " test notification(s)");
        } else if (sCmd.Equals("ALWAYS")) {
            CString sVal = sCommand.Token(1).AsLower();
            if (sVal == "on" || sVal == "off") {
                m_bAlways = sVal == "on";
                SetNV("always", m_bAlways ? "1" : "0");
            }
            PutModule(CString("Push even while clients are present: ") + (m_bAlways ? "on" : "off"));
        } else if (sCmd.Equals("RULES")) {
            CUser* pUser = GetUser();
            if (!pUser) { PutModule("No user context"); return; }
            const CString sNet = GetNetwork() ? GetNetwork()->GetName() : CString();
            CTable t;
            t.AddColumn("Scope");
            t.AddColumn("Kind");
            t.AddColumn("Value");
            for (const CString& sScope : {CString(), sNet}) {
                for (const Rule& r : RulesFor(pUser, sScope)) {
                    t.AddRow();
                    t.SetCell("Scope", sScope.empty() ? "(all networks)" : sScope);
                    t.SetCell("Kind", r.sKind);
                    t.SetCell("Value", r.sValue);
                }
                if (sNet.empty()) break;
            }
            if (t.empty()) PutModule("No push rules" + (sNet.empty() ? CString() : " for " + sNet));
            else PutModule(t);
        } else if (sCmd.Equals("RULE")) {
            CUser* pUser = GetUser();
            if (!pUser) { PutModule("No user context"); return; }
            const CString sNet = GetNetwork() ? GetNetwork()->GetName() : CString();
            const CString sScope = sNet.empty() ? "all networks" : sNet;
            CString sAction = sCommand.Token(1).AsUpper(), sKind = sCommand.Token(2).AsLower(), sValue = sCommand.Token(3, true);
            CString sError;
            if (sAction == "CLEAR") {
                if (!sKind.empty() && !ValidKind(sKind)) { PutModule("Unknown rule kind " + sKind); return; }
                ClearRules(pUser, sNet, sKind);
                PutModule("Cleared " + (sKind.empty() ? CString("all") : sKind) + " rules for " + sScope);
            } else if (sAction == "ADD" || sAction == "DEL") {
                bool bOk = sAction == "ADD" ? AddRule(pUser, sNet, sKind, sValue, sError)
                                            : DelRule(pUser, sNet, sKind, sValue, sError);
                PutModule(bOk ? (sAction == "ADD" ? "Added " : "Removed ") + sKind + " rule \"" + sValue + "\" for " + sScope : sError);
            } else {
                PutModule("Usage: rule add|del <kind> <value>, rule clear [<kind>]; kinds: highlight, mute, all, ignore");
            }
        } else {
            PutModule("Commands: list, test, always on|off, rules, rule add|del <kind> <value>, rule clear [<kind>]");
        }
    }

    void SubscriptionGone(const CString& sSubKey) { DelNV(sSubKey); }

    // Grace period over: push unless a read marker says it was read.
    void FirePending(const CPendingPush& t) {
        CUser* pUser = CZNC::Get().FindUser(t.m_sUser);
        CIRCNetwork* pNet = pUser ? pUser->FindNetwork(t.m_sNet) : nullptr;
        if (!pNet) return;
        if (m_bAlways || !WasRead(pNet, t.m_sTarget, t.m_sTime)) PushAll(pUser, pNet, t.m_sLine);
    }

  private:
    static CString NetName(const CClient* pClient) {
        return pClient->GetNetwork() ? pClient->GetNetwork()->GetName() : CString();
    }
    static CString SubKey(const CUser* pUser, const CString& sNet, const CString& sEndpoint) {
        return "sub:" + pUser->GetUsername() + ":" + sNet + ":" + sEndpoint;
    }
    // "<net>:<endpoint>" (net may be empty; endpoints contain ':').
    static void SplitKey(const CString& sRest, CString& sNet, CString& sEndpoint) {
        sNet = sRest.Token(0, false, ":", true);
        sEndpoint = sRest.Token(1, true, ":", true);
    }

    // Old entries "sub:<user>:<endpoint>" with net=... inside the value.
    void MigrateSubscriptions() {
        std::vector<std::pair<CString, CString>> vOld;
        for (auto it = BeginNV(); it != EndNV(); ++it) {
            if (!it->first.StartsWith("sub:")) continue;
            CString sRest = CString(it->first.substr(4)).Token(1, true, ":", true);
            if (sRest.StartsWith("http://") || sRest.StartsWith("https://")) vOld.emplace_back(it->first, it->second);
        }
        for (const auto& kv : vOld) {
            CString sUser = CString(kv.first.substr(4)).Token(0, false, ":", true);
            CString sEndpoint = CString(kv.first.substr(4)).Token(1, true, ":", true);
            MCString sub = ircv3::DecodeAttrs(kv.second);
            CString sNet = sub["net"];
            sub.erase("net");
            DelNV(kv.first, false);
            SetNV("sub:" + sUser + ":" + sNet + ":" + sEndpoint, ircv3::EncodeAttrs(sub), false);
        }
        if (!vOld.empty()) SaveRegistry();
    }

    // A client that would see the message right now: attached to the
    // network, not away, not on its way out.
    static bool HasPresentClient(const CIRCNetwork* pNet) {
        for (CClient* pClient : pNet->GetClients())
            if (!pClient->IsAway() && !pClient->IsClosed()) return true;
        return false;
    }

    static bool WasRead(const CIRCNetwork* pNet, const CString& sTarget, const CString& sTime) {
        CModule* pMod = CZNC::Get().GetModules().FindModule("readmarker");
        if (!pMod) return false;
        CString sMarker = pMod->GetNV("marker:" + pNet->GetUser()->GetUsername() + ":" + pNet->GetName() + ":" + sTarget.AsLower());
        return !sMarker.empty() && sMarker >= sTime;
    }

    // ---- push rules ----------------------------------------------------

    static CString ScopeKey(const CUser* pUser, const CString& sNet) { return pUser->GetUsername() + ":" + sNet; }
    static CString RuleKey(const CUser* pUser, const CString& sNet, const CString& sKind, const CString& sValue) {
        return "rule:" + pUser->GetUsername() + ":" + sNet + ":" + sKind + ":" + sValue;
    }

    const std::vector<Rule>& RulesFor(const CUser* pUser, const CString& sNet) {
        return m_mRules[ScopeKey(pUser, sNet)];
    }

    void LoadRules() {
        m_mRules.clear();
        for (auto it = BeginNV(); it != EndNV(); ++it) {
            if (!it->first.StartsWith("rule:")) continue;
            CString sRest = it->first.substr(5);
            CString sUser = sRest.Token(0, false, ":", true), sNet = sRest.Token(1, false, ":", true);
            Rule r;
            r.sKind = sRest.Token(2, false, ":", true);
            r.sValue = sRest.Token(3, true, ":", true);
            CString sError;
            if (!ValidKind(r.sKind) || !r.Compile(sError)) continue;
            m_mRules[sUser + ":" + sNet].push_back(std::move(r));
        }
    }

    bool AddRule(CUser* pUser, const CString& sNet, const CString& sKind, const CString& sValue, CString& sError) {
        if (!ValidKind(sKind)) { sError = "Unknown rule kind " + (sKind.empty() ? "*" : sKind); return false; }
        if (sValue.empty()) { sError = "Empty rule value"; return false; }
        if (sValue.size() > kMaxRuleValue) { sError = "Rule value longer than " + CString(kMaxRuleValue) + " bytes"; return false; }
        std::vector<Rule>& v = m_mRules[ScopeKey(pUser, sNet)];
        for (const Rule& r : v)
            if (r.sKind == sKind && r.sValue == sValue) return true;  // already there
        if (v.size() >= kMaxRulesPerScope) { sError = "Too many rules (limit " + CString(kMaxRulesPerScope) + ")"; return false; }
        Rule r;
        r.sKind = sKind;
        r.sValue = sValue;
        if (!r.Compile(sError)) return false;
        v.push_back(std::move(r));
        SetNV(RuleKey(pUser, sNet, sKind, sValue), "1");
        return true;
    }

    bool DelRule(CUser* pUser, const CString& sNet, const CString& sKind, const CString& sValue, CString& sError) {
        if (!ValidKind(sKind)) { sError = "Unknown rule kind " + (sKind.empty() ? "*" : sKind); return false; }
        if (sValue.empty()) { sError = "Empty rule value"; return false; }
        std::vector<Rule>& v = m_mRules[ScopeKey(pUser, sNet)];
        for (auto it = v.begin(); it != v.end(); ++it)
            if (it->sKind == sKind && it->sValue == sValue) { v.erase(it); break; }
        DelNV(RuleKey(pUser, sNet, sKind, sValue));
        return true;
    }

    void ClearRules(CUser* pUser, const CString& sNet, const CString& sKind) {
        std::vector<Rule>& v = m_mRules[ScopeKey(pUser, sNet)];
        for (auto it = v.begin(); it != v.end();) {
            if (sKind.empty() || it->sKind == sKind) {
                DelNV(RuleKey(pUser, sNet, it->sKind, it->sValue), false);
                it = v.erase(it);
            } else {
                ++it;
            }
        }
        SaveRegistry();
    }

    void SendRules(CClient* pClient, CUser* pUser, const CString& sNet) {
        bool bBatch = pClient->HasBatch();
        CString sRef = "pr" + ircv3::RandomId(8);
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH +" + sRef + " " + kRulesBatch);
        for (const Rule& r : RulesFor(pUser, sNet)) {
            CString sLine = ":irc.znc.in WEBPUSH RULE " + r.sKind + " :" + r.sValue;
            if (bBatch) sLine = "@batch=" + sRef + " " + sLine;
            pClient->PutClient(sLine);
        }
        if (bBatch) pClient->PutClient(":irc.znc.in BATCH -" + sRef);
    }

    // The decision order from docs/webpush-rules.md. sBuffer is the channel
    // or the sender's nick; bDirect marks PMs and INVITEs to the user.
    bool Decide(CIRCNetwork* pNet, const CNick& Sender, const CString& sBuffer, bool bDirect, const CString& sText) {
        CUser* pUser = pNet->GetUser();
        const std::vector<Rule>* scopes[2] = {&RulesFor(pUser, ""), &RulesFor(pUser, pNet->GetName())};
        CString sMapping = pNet->GetIRCSock() ? pNet->GetIRCSock()->GetISupport("CASEMAPPING", "rfc1459") : "rfc1459";
        const CString sBufferFolded = FoldName(sBuffer, sMapping);
        auto any = [&](const char* sKind, auto&& pred) {
            for (const std::vector<Rule>* v : scopes)
                for (const Rule& r : *v)
                    if (r.sKind == sKind && pred(r)) return true;
            return false;
        };
        if (any("ignore", [&](const Rule& r) { return r.MatchesSender(Sender); })) return false;
        if (any("mute", [&](const Rule& r) { return FoldName(r.sValue, sMapping) == sBufferFolded; })) return false;
        if (bDirect) return true;
        if (any("all", [&](const Rule& r) { return FoldName(r.sValue, sMapping) == sBufferFolded; })) return true;
        const CString sNick = pNet->GetCurNick();
        if (!sNick.empty() && WordMatch(sText.AsLower(), sNick.AsLower())) return true;
        return any("highlight", [&](const Rule& r) { return r.MatchesText(sText); });
    }

    void Consider(CTextMessage& M, bool bPrivate) {
        CIRCNetwork* pNet = M.GetNetwork() ? M.GetNetwork() : GetNetwork();
        if (!pNet || M.GetNick().NickEquals(pNet->GetCurNick())) return;  // our own (echoed) messages
        const CString sBuffer = bPrivate ? M.GetNick().GetNick() : M.GetTarget();
        if (!Decide(pNet, M.GetNick(), sBuffer, bPrivate, M.GetText())) return;
        Schedule(pNet, M, sBuffer);
    }

    // Push now, or after the grace period when a client is present.
    void Schedule(CIRCNetwork* pNet, const CMessage& M, const CString& sTarget) {
        CMessage copy(M);
        MCString tags;
        for (const auto& kv : M.GetTags())
            if (kv.first == "msgid" || kv.first == "account") tags[kv.first] = kv.second;
        const CString sTime = CUtils::FormatServerTime(M.GetTime());
        tags["time"] = sTime;
        copy.SetTags(tags);
        if (m_bAlways || !HasPresentClient(pNet)) {
            PushAll(pNet->GetUser(), pNet, copy.ToString());
            return;
        }
        AddTimer(new CPendingPush(this, pNet->GetUser()->GetUsername(), pNet->GetName(), sTarget, sTime, copy.ToString()));
    }

    int PushAll(CUser* pUser, CIRCNetwork* pNet, const CString& sLine) {
        const CString sPrefix = "sub:" + pUser->GetUsername() + ":";
        // endpoint -> (key, keys); network-bound entries first, unbound
        // ones only for endpoints without one.
        std::map<CString, std::pair<CString, MCString>> chosen;
        std::vector<std::pair<CString, CString>> generic;  // key, endpoint
        for (auto it = BeginNV(); it != EndNV(); ++it) {
            if (!it->first.StartsWith(sPrefix)) continue;
            CString sNet, sEndpoint;
            SplitKey(it->first.substr(sPrefix.size()), sNet, sEndpoint);
            if (sNet.empty()) generic.emplace_back(it->first, sEndpoint);
            else if (!pNet || sNet == pNet->GetName()) chosen[sEndpoint] = {it->first, ircv3::DecodeAttrs(it->second)};
        }
        for (const auto& kv : generic)
            if (!chosen.count(kv.second)) chosen[kv.second] = {kv.first, ircv3::DecodeAttrs(GetNV(kv.first))};
        int n = 0;
        for (const auto& kv : chosen)
            if (Push(kv.second.first, kv.first, kv.second.second, sLine)) n++;
        return n;
    }

    bool Push(const CString& sSubKey, const CString& sEndpoint, const MCString& sub, const CString& sLine) {
        Url u;
        if (!ParseUrl(sEndpoint, u)) return false;
        CString sBody = EncryptAes128Gcm(sLine, B64UrlDecode(sub.at("p256dh")), B64UrlDecode(sub.at("auth")));
        if (sBody.empty()) return false;
        // VAPID JWT
        CString sHeader = B64Url("{\"typ\":\"JWT\",\"alg\":\"ES256\"}");
        CString sClaims = B64Url("{\"aud\":\"" + u.sOrigin + "\",\"exp\":" + CString(time(nullptr) + 12 * 3600) +
                                 ",\"sub\":\"" + m_sContact + "\"}");
        CString sSig = B64Url(SignES256(m_Vapid.key, sHeader + "." + sClaims));
        CString sJwt = sHeader + "." + sClaims + "." + sSig;
        CString sReq = "POST " + u.sPath + " HTTP/1.1\r\nHost: " + u.sHost + "\r\nContent-Type: application/octet-stream\r\n"
                       "Content-Encoding: aes128gcm\r\nContent-Length: " + CString(sBody.size()) + "\r\nTTL: " + CString(m_uTTL) +
                       "\r\nUrgency: high\r\nAuthorization: vapid t=" + sJwt + ", k=" + m_sVapidPub +
                       "\r\nConnection: close\r\n\r\n" + sBody;
        CPushRequest* pReq = new CPushRequest(this, sSubKey, u, sReq);
        pReq->SetSockName("webpush::" + u.sHost);
        AddSocket(pReq);
        pReq->Connect(u.sHost, u.uPort, u.bTLS);
        return true;
    }

    CapTracker m_Caps;
    std::map<CString, std::vector<Rule>> m_mRules;  // "<user>:<network>" -> rules
    ircv3::ISupportBurst m_Burst{{"VAPID"}};
    ECKey m_Vapid;
    CString m_sVapidPub, m_sContact;
    unsigned m_uTTL = 86400;
    bool m_bAlways = false;
};

void CPendingPush::RunJob() { static_cast<CWebPush*>(GetModule())->FirePending(*this); }

void CPushRequest::Disconnected() {
    if (m_bGone) static_cast<CWebPush*>(GetModule())->SubscriptionGone(m_sSubKey);
}

template <>
void TModInfo<CWebPush>(CModInfo& Info) {
    Info.SetWikiPage("webpush");
    Info.SetHasArgs(true);
    Info.SetArgsHelpText("[ttl=<seconds>] [always] [contact=<mailto:...|https://...>]");
}

GLOBALMODULEDEFS(CWebPush, "soju.im/webpush: Web Push notifications for highlights and private messages")
