#include <zephyr/sys/base64.h>
#include "pem-decode.h"
#include <stdbool.h>

size_t pemExpectedSize(enum DerObjectType type)
{
    switch (type)
    {
    case EC_P256_PRIVATE_KEY:
        return 32;
    case EC_P256_PUBLIC_KEY:
        return 64;
    case EC_P256_SIGNATURE:
        return 64;
    default:
        return 0;
    }
}

bool find_pem_base64(const char *text, size_t text_len, size_t *start, size_t *end)
{
    const char *begin_marker = "-----BEGIN";
    const char *end_marker = "-----END";

    // Search for the start of the PEM block
    const char *begin = strstr(text, begin_marker);
    if (begin == NULL)
    {
        return false;
    }

    // Move the pointer past the "-----BEGIN" marker
    begin += strlen(begin_marker);

    // Search for the end of the PEM block
    const char *pem_end = strstr(begin, end_marker);
    if (pem_end == NULL)
    {
        return false;
    }

    // Move the pointer past the "-----" to find the start of the Base64 data
    const char *b64_start = strstr(begin, "-----");
    if (b64_start == NULL || b64_start >= pem_end)
    {
        return false;
    }
    b64_start += 5;

    *start = b64_start - text;
    *end = pem_end - text;

    return true;
}

int pemDecode(const char *pem, enum DerObjectType type, uint8_t *data, size_t *len)
{
    int pem_len = strlen(pem);

    size_t start = 0, end = pem_len;

    bool hasHeader = false;

    // see if data contains header/footer
    for (size_t i = 0; i < pem_len; i++)
    {
        if (pem[i] == '-')
        {
            hasHeader = true;
            break;
        }
    }

    if (hasHeader)
    {
        if (!find_pem_base64(pem, pem_len, &start, &end))
        {
            return -1;
        }
    }

    if (start >= end)
    {
        return -1;
    }

    uint8_t der[pem_len * 4 / 3 + 3];
    size_t der_len = 0;

    if (base64_decode(der, sizeof(der), der_len, pem + start, end - start) != 0)
    {
        return -1;
    }
}