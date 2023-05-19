#include <stdint.h>

#ifndef KEYS_H
#define KEYS_H

struct BootAuthenticator
{
    const char *name;
    const char *variantPattern;
    const char *pubKey;
};

#define BOOT_AUTHENTICATOR_COUNT 1

static const struct BootAuthenticator bootAuthenticators[BOOT_AUTHENTICATOR_COUNT] = {
    {.name = "Zodiac",
     .variantPattern = "*",
     .pubKey =
         "-----BEGIN PUBLIC KEY-----"
         "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEzplyt9lz+PlpjGRAGEaxC75HgKU"
         "QH9vc8gwngoc9dq1BHffQFEXJ3dO4+otvF9C44ALki/QxX13rG4QJqOJ3w=="
         "-----END PUBLIC KEY-----"},
};

static const char *rocketZPub =
    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE70rS77CvKXulXM1Cx0CqbnMcuaA5"
    "1pNE2qWsmlcJGNOjSScD1C+cpzd6JVTd63LnV1cmCabNCmjCpPM/A9+xCA=="
    "-----END PUBLIC KEY-----";

#endif // KEYS_H