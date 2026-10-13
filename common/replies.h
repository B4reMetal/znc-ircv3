// Standard replies (https://ircv3.net/specs/extensions/standard-replies)
// and small helpers for sending lines from "irc.znc.in" to one client.
#pragma once
#include <znc/Client.h>
#include <znc/ZNCString.h>
#include <vector>

namespace ircv3 {

inline const char* kServer = "irc.znc.in";

inline void PutReply(CClient* pClient, const CString& sKind,
                     const CString& sCommand, const CString& sCode,
                     const VCString& vsContext, const CString& sDescription) {
    if (!pClient) return;
    CString sLine = ":" + CString(kServer) + " " + sKind + " " + sCommand +
                    " " + sCode;
    for (const CString& s : vsContext) sLine += " " + s;
    sLine += " :" + sDescription;
    pClient->PutClient(sLine);
}

inline void PutFail(CClient* pClient, const CString& sCommand,
                    const CString& sCode, const VCString& vsContext,
                    const CString& sDescription) {
    PutReply(pClient, "FAIL", sCommand, sCode, vsContext, sDescription);
}

inline void PutWarn(CClient* pClient, const CString& sCommand,
                    const CString& sCode, const VCString& vsContext,
                    const CString& sDescription) {
    PutReply(pClient, "WARN", sCommand, sCode, vsContext, sDescription);
}

inline void PutNote(CClient* pClient, const CString& sCommand,
                    const CString& sCode, const VCString& vsContext,
                    const CString& sDescription) {
    PutReply(pClient, "NOTE", sCommand, sCode, vsContext, sDescription);
}

}  // namespace ircv3
