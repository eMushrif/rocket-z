/**
 * @file pem-decode.h
 * @brief PEM parser
 */

#ifndef __PEM_DECODE_H__
#define __PEM_DECODE_H__

#include <stddef.h>
#include "tiny-asn1.h"

enum DerObjectType
{
    EC_P256_PRIVATE_KEY = 0, // size 32 bytes
    EC_P256_PUBLIC_KEY,      // size 64 bytes
    EC_P256_SIGNATURE,       // size 64 bytes
};

/**
 * @brief Parse PEM text. Text can be with or without header and footer. Data might be written even if format is not recognized.
 * @param pem PEM text
 * @param type DER object type
 * @param data DER object data output
 * @param len DER object data output actual length
 * @return 0 if success, -1 if format error or object not found
 */
int pemDecode(const char *pem, enum DerObjectType type, uint8_t *data, size_t *len = NULL);

/**
 * @brief Get expected size of DER data
 * @param type DER object type
 * @return expected size
 */
size_t pemExpectedSize(enum DerObjectType type);

#endif // __PEM_DECODE_H__