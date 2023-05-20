#include <zephyr/sys/base64.h>
#include <stdbool.h>
#include "pem-decode.h"
#include "tiny-asn1.h"
#include <string.h>
#include <zephyr/kernel.h>

K_HEAP_DEFINE(pem_heap, 1024);

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

bool findIdentifier(const asn1_tree *tree, int objectCount, const uint8_t *identifierData, size_t identifierDataSize);
asn1_tree *findObject(asn1_tree *tree, int objectCount, uint8_t tag, size_t minimumSize, size_t expectedSize);

int pemExtract(const char *pem, enum DerObjectType type, uint8_t *data, size_t *len)
{
    if (NULL == pem || NULL == data)
        return -EINVAL;

    int pem_len = strlen(pem);

    if (NULL != len)
        *len = 0;

    size_t start = 0, end = pem_len;

    bool hasDelimiters = false;

    // see if data contains header/footer
    if (strchr(pem, '-'))
        hasDelimiters = true;

    if (hasDelimiters)
    {
        if (!find_pem_base64(pem, pem_len, &start, &end))
        {
            return -EINVAL;
        }
    }

    if (start >= end)
    {
        return -EINVAL;
    }

    uint8_t der[1024];
    size_t der_len = 0;

    if (base64_decode(der, sizeof(der), &der_len, pem + start, end - start) != 0)
    {
        return -EINVAL;
    }

    // parse ASN.1 DER

    // The following is a HACK for OpenSSL-generated keys because their ASN.1 structure is not standard (?)

    if (der_len > 130 && der[2] == 0x87)
    {
        if (der[27] == 0x04 && der[28] >= 100)
            der[27] |= 0x20; // make it a constructed type
    }

    int32_t asn1_object_count = der_object_count(der, der_len);
    if (asn1_object_count <= 0)
    {
        // failed to read object count or empty object
        return -EINVAL;
    }

    k_heap_init(&pem_heap, pem_heap.heap.init_mem, pem_heap.heap.init_bytes);
    asn1_tree *asn1_objects = (asn1_tree *)(k_heap_alloc(&pem_heap, sizeof(asn1_tree) * asn1_object_count, K_NO_WAIT));
    if (asn1_objects == NULL)
    {
        // failed to allocate
        return -2000;
    }

    if (der_decode(der, der_len, asn1_objects, asn1_objects + 1, asn1_object_count) < 0)
    {
        // failed to decode
        k_heap_free(&pem_heap, asn1_objects);
        return -2000;
    }

    // find the object we're looking for

    bool identifierFound = false;

    const uint8_t primev251v1_identifier[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

    if (type == EC_P256_PRIVATE_KEY)
    {
        identifierFound = /*findIdentifier(asn1_objects, asn1_object_count, ecPublicKey_identifier, sizeof(ecPublicKey_identifier)) &&*/ findIdentifier(asn1_objects, asn1_object_count, primev251v1_identifier, sizeof(primev251v1_identifier));

        asn1_tree *object = findObject(asn1_objects, asn1_object_count, ASN1_TYPE_OCTET_STRING, pemExpectedSize(type), pemExpectedSize(type));

        if (NULL == object)
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        if (object->length < pemExpectedSize(type))
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        // copy object data without prefixes
        memcpy(data, object->data + (object->length - pemExpectedSize(type)), pemExpectedSize(type));
    }
    else if (type == EC_P256_PUBLIC_KEY)
    {
        identifierFound = /*findIdentifier(asn1_objects, asn1_object_count, ecPublicKey_identifier, sizeof(ecPublicKey_identifier)) &&*/ findIdentifier(asn1_objects, asn1_object_count, primev251v1_identifier, sizeof(primev251v1_identifier));

        asn1_tree *object = findObject(asn1_objects, asn1_object_count, ASN1_TYPE_BIT_STRING, pemExpectedSize(type), 2 + pemExpectedSize(type)); // pub key data usually have 2 bytes prefix

        if (NULL == object)
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        if (object->length < pemExpectedSize(type))
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        // copy object data without prefixes
        memcpy(data, object->data + (object->length - pemExpectedSize(type)), pemExpectedSize(type));
    }
    else if (type == EC_P256_SIGNATURE)
    {
        identifierFound = true; // no identifier object for signatures

        // signature message have 2 objects of interest
        // sometimes they can be of size 32 or 33, or one can be 32 and the other 33
        // but they come in the same order always (hopefully)
        // the data we need from each object is always 32 bytes

        asn1_tree *certObject;
        asn1_tree *algoObject;

        int maxCertSearch = asn1_object_count;

    sign_search:

        certObject = findObject(asn1_objects, maxCertSearch, ASN1_TYPE_INTEGER, 32, 32);

        if (NULL == certObject)
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        if (certObject->length < 32)
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        // algoObject comes after certObject

        algoObject = findObject(certObject + 1, asn1_object_count - (certObject - asn1_objects) - 1, ASN1_TYPE_INTEGER, 32, 32);

        if (NULL == algoObject)
        {
            // sometimes certObject takes algoObject data on the first try
            // and no objects after it fit for algoObject
            // so, limit the search of certObject to the first few objects
            // and retry

            if (certObject > asn1_objects)
            {
                maxCertSearch = certObject - asn1_objects;
                goto sign_search;
            }

            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        if (algoObject->length < 32)
        {
            k_heap_free(&pem_heap, asn1_objects);
            return -EINVAL;
        }

        memcpy(data, certObject->data + (certObject->length - 32), 32);
        memcpy(data + 32, algoObject->data + (algoObject->length - 32), 32);
    }

    if (NULL != len)
        *len = pemExpectedSize(type);

    k_heap_free(&pem_heap, asn1_objects);

    return identifierFound ? 0 : -1;
}

enum ValidityLevel
{
    NOT_MATCHING = 0,
    SIZE_LARGER_OR_EQUAL,
    SIZE_EXACT,
    TAG_MATCH = 0x80,
};

bool findIdentifier(const asn1_tree *tree, int objectCount, const uint8_t *identifierData, size_t identifierDataSize)
{
    for (int i = 0; i < objectCount; i++)
    {
        if (tree[i].type == 0x06)
        {
            if (tree[i].length == identifierDataSize)
            {
                if (memcmp(tree[i].data, identifierData, identifierDataSize) == 0)
                {
                    return true;
                }
            }
        }
    }

    return false;
}

#ifndef ABS
#define ABS(a) (((a) < 0) ? -(a) : (a))
#endif

asn1_tree *findObject(asn1_tree *tree, int objectCount, uint8_t tag, size_t minimumSize, size_t expectedSize)
{
    enum ValidityLevel validity = NOT_MATCHING;
    asn1_tree *candidate = NULL;

    for (int i = 0; i < objectCount; i++)
    {
        enum ValidityLevel currentValidity = NOT_MATCHING;

        if (tree[i].length >= minimumSize)
        {
            currentValidity = SIZE_LARGER_OR_EQUAL;

            if (tree[i].length == expectedSize)
                currentValidity = SIZE_EXACT;

            if (tree[i].type == tag)
                currentValidity |= TAG_MATCH;

            if (currentValidity > validity)
            {
                validity = currentValidity;
                candidate = &tree[i];
            }
            else if (currentValidity == validity && validity == SIZE_LARGER_OR_EQUAL)
            {
                // find most fitting size
                validity = currentValidity;
                candidate = ABS(tree[i].length - expectedSize) < ABS(candidate->length - expectedSize) ? &tree[i] : candidate;
            }

            if (validity == (TAG_MATCH | SIZE_EXACT))
            {
                break;
            }
        }
    }

    return candidate;
}