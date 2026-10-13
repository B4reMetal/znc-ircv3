// Random identifiers safe for use as batch references and message-tag
// values. CString::RandomString() draws from a set that includes ';', ' '
// lookalikes and other punctuation that is illegal in a tag value or a
// batch reference, so it must not be used for those.
#pragma once
#include <znc/ZNCString.h>
#include <random>

namespace ircv3 {

inline CString RandomId(size_t uLength) {
    static const char kChars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, sizeof(kChars) - 2);
    CString sRet;
    sRet.reserve(uLength);
    for (size_t i = 0; i < uLength; ++i) sRet += kChars[dist(rng)];
    return sRet;
}

}  // namespace ircv3
