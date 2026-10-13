// Message-tag style attribute lists: key=value;key2=value2
// Used by bouncer-networks (network attributes) and anything else that
// carries key/value pairs in a single parameter. Escaping follows the
// message-tags spec: ';' -> '\:', ' ' -> '\s', '\' -> '\\', CR -> '\r',
// LF -> '\n'.
#pragma once
#include <znc/ZNCString.h>
#include <map>

namespace ircv3 {

inline CString EscapeTagValue(const CString& s) {
    CString out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case ';': out += "\\:"; break;
            case ' ': out += "\\s"; break;
            case '\\': out += "\\\\"; break;
            case '\r': out += "\\r"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out;
}

inline CString UnescapeTagValue(const CString& s) {
    CString out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] != '\\' || i + 1 >= s.size()) { out += s[i]; continue; }
        char n = s[++i];
        switch (n) {
            case ':': out += ';'; break;
            case 's': out += ' '; break;
            case '\\': out += '\\'; break;
            case 'r': out += '\r'; break;
            case 'n': out += '\n'; break;
            default: out += n;
        }
    }
    return out;
}

inline CString EncodeAttrs(const MCString& mss) {
    CString out;
    for (const auto& kv : mss) {
        if (!out.empty()) out += ";";
        out += kv.first;
        if (!kv.second.empty()) out += "=" + EscapeTagValue(kv.second);
    }
    return out;
}

// Keys without '=' get an empty value (the spec's "attribute removed").
inline MCString DecodeAttrs(const CString& sAttrs) {
    MCString mss;
    VCString vs;
    sAttrs.Split(";", vs, false);
    for (const CString& s : vs) {
        CString::size_type eq = s.find('=');
        if (eq == CString::npos)
            mss[s] = "";
        else
            mss[s.substr(0, eq)] = UnescapeTagValue(s.substr(eq + 1));
    }
    return mss;
}

}  // namespace ircv3
