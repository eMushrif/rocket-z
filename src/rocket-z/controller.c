#include "controller.h"
#include <stdarg.h>
#include <string.h>
#include "keys.h"
#include <zephyr/data/json.h>
#include <zephyr/sys/base64.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dsa.h>

struct BootInfoBuffer
{
    struct BootInfo bootInfo[2];
};

struct BootInfo *bootInfo_load(uint32_t address)
{

    struct BootInfo *result = (struct BootInfo *)k_malloc(sizeof(struct BootInfoBuffer));

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, result, sizeof(struct BootInfo));

    if (result->version != BOOT_VERSION_0_0)
    {
        // Boot information not loaded, or different version. Reset info.
        memset(result, 0, sizeof(struct BootInfo));

        // set bootloader name
        strcpy(result->bootloaderName, "rocket-zn");

        // set boot version
        result->version = BOOT_VERSION_0_0;

        // reset image status
        for (int i = 0; i < ARRAY_SIZE(result->img); i++)
        {
            image_clearLoadRequest(&result->img[i]);
            result->img[i].imageInfo.strikeCountResetVal = 0x07;
            result->img[i].isValid = false;
        }
    }

    // copy the original boot info to the second half of the buffer
    memcpy(&((struct BootInfoBuffer *)result)->bootInfo[1], &((struct BootInfoBuffer *)result)->bootInfo[0], sizeof(struct BootInfo));

    return result;
}

void bootInfo_save(uint32_t address, const struct BootInfo *info)
{
    struct BootInfoBuffer *buffer = info;

    // if info is the same as the one in flash, don't write it
    if (memcmp(&buffer->bootInfo[1], &buffer->bootInfo[0], sizeof(struct BootInfo)) == 0)
        return;

    // if any bits were changed from 0 to 1, erase the flash page
    for (int i = 0; i < sizeof(struct BootInfo); i++)
    {
        if (((uint8_t *)&buffer->bootInfo[0])[i] & ~((uint8_t *)&buffer->bootInfo[1])[i])
        {
            bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, FLASH_BLOCK_SIZE);
            break;
        }
    }

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));

    // double check that the write was successful
    // copy the updated boot info to the second half of the buffer
    memcpy(&buffer->bootInfo[1], &buffer->bootInfo[0], sizeof(struct BootInfo));

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, &buffer->bootInfo[0], sizeof(struct BootInfo));
    if (memcmp(&buffer->bootInfo[1], &buffer->bootInfo[0], sizeof(struct BootInfo)) != 0)
    {
        // data wasn't written correctly. erase and write again
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, sizeof(struct BootInfo));
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));
    }
}

void bootInfo_free(struct BootInfo *info)
{
    if (NULL != info)
    {
        free(info);
        info = NULL;
    }
}

void image_setName(struct ImageInfo *info, const char *name)
{
    if (strlen(name) <= sizeof(info->imageName) - 1)
        strcpy(info->imageName, name);
}

void image_setStorage(struct ImageStore *info, size_t address, enum ImageStorage storage, size_t maxSize)
{
    info->startAddr = address;
    info->storage = storage;
}

void image_setSignature(struct ImageInfo *info, const char *message, const char *signature)
{
    if (strlen(message) <= sizeof(info->signatureInfo.message) - 1)
        strcpy(info->signatureInfo.message, message);

    int len;
    base64_decode(info->signatureInfo.signature, sizeof(info->signatureInfo.signature), len, message, strlen(message));
}

void image_setEncryption(struct ImageInfo *info, const char *pubKey, enum EncryptionMethod method, size_t encryptedSize)
{
    int len;
    base64_decode(info->encryption.pubKey, sizeof(info->encryption.pubKey), len, pubKey, strlen(pubKey));

    info->encryption.method = method;
    info->encryption.encryptedSize = encryptedSize;

    // invalidate the image
    image_setFlag(info, BOOT_IMG_INVALID);
}

void image_setValid(struct ImageStore *info, bool valid)
{
    info->isValid = valid;
}

void bootInfo_setCurrentVariant(struct BootInfo *info, const char *variant)
{
    if (strlen(variant) <= sizeof(info->currentVariant) - 1)
        strcpy(info->currentVariant, variant);
}

void image_setLoadRequest(struct ImageInfo *info)
{
    if (0 == info->loadRequests)
    {
        info->loadRequests = -1;
    }

    for (int i = 0; i < 8 * sizeof(info->loadRequests); i++)
    {
        if ((1 << i) & info->loadRequests)
        {
            info->loadRequests &= ~(1 << i);
            return;
        }
    }
}

void image_clearLoadRequest(struct ImageInfo *info)
{
    info->loadAttempts = info->loadRequests;
}

bool image_hasLoadRequest(struct ImageInfo *info)
{
    return info->loadRequests != info->loadAttempts;
}

bool image_isCurrent(struct ImageInfo *info, struct BootInfo *bootInfo)
{
    return 0 == memcmp(&info->signatureInfo, &bootInfo->currentImage.signatureInfo, sizeof(info->signatureInfo));
}

bool isMatch(const char *str, const char *pattern)
{

    if (NULL == str || NULL == pattern)
        return false;

    int str_len = strlen(str);
    int pattern_len = strlen(pattern);
    // dry run this sample case on paper , if unable to understand what soln does
    // p = "a*bc" s = "abcbc"
    int sIdx = 0, pIdx = 0, lastWildcardIdx = -1, sBacktrackIdx = -1,
        nextToWildcardIdx = -1;
    while (sIdx < str_len)
    {
        if (pIdx < pattern_len &&
            (pattern[pIdx] == '?' || pattern[pIdx] == str[sIdx]))
        {
            // chars match
            ++sIdx;
            ++pIdx;
        }
        else if (pIdx < pattern_len && pattern[pIdx] == '*')
        {
            // wildcard, so chars match - store index.
            lastWildcardIdx = pIdx;
            nextToWildcardIdx = ++pIdx;
            sBacktrackIdx = sIdx;

            // storing the pidx+1 as from there I want to match the remaining pattern
        }
        else if (lastWildcardIdx == -1)
        {
            // no match, and no wildcard has been found.
            return false;
        }
        else
        {
            // backtrack - no match, but a previous wildcard was found.
            pIdx = nextToWildcardIdx;
            sIdx = ++sBacktrackIdx;
            // backtrack string from previousbacktrackidx + 1 index to see if then new
            // pidx and sidx have same chars, if that is the case that means wildcard
            // can absorb the chars in b/w and still further we can run the algo, if
            // at later stage it fails we can backtrack
        }
    }
    for (int i = pIdx; i < pattern_len; i++)
    {
        if (pattern[i] != '*')
            return false;
    }
    return true;
    // true if every remaining char in p is wildcard
}

#define DESCR_ARRAY_SIZE 7

struct json_obj_descr descr[DESCR_ARRAY_SIZE] = {
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, version, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, provider, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, userId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, time, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, variantPattern, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, size, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct SignatureMessage, sha256, JSON_TOK_STRING),
};

bool image_verifySignature(const struct ImageStore *store, const struct BootInfo *bootInfo, struct SignatureMessage *message)
{
    if (!store->isValid)
    {
        bootLog("ERROR: Image %s is marked not valid", store->imageInfo.imageName);
        return false;
    }

    int parseResult = json_obj_parse(store->imageInfo.signatureInfo.message, strlen(store->imageInfo.signatureInfo.message), descr, DESCR_ARRAY_SIZE, message);

    if (!((parseResult & 127) == 127))
    {
        for (int i = 0; i < DESCR_ARRAY_SIZE; i++)
        {
            if (!(parseResult & (1 << i)))
            {
                bootLog("ERROR: Image %s signature message is missing field %s", store->imageInfo.imageName, descr[i].field_name);
            }
        }
        bootLog("ERROR: Image %s has invalid signature message", store->imageInfo.imageName);
        return false;
    }

#if 0 // Checking variant pattern match should be done by the application
    if (!isMatch(bootInfo->currentVariant, message->variantPattern))
    {
        bootLog("ERROR: Image %s is signed for pattern %s that doesn't match current variant (%s)", store->imageInfo.imageName, message->variantPattern, bootInfo->currentVariant);
        bootLog("HINT: use bootInfo_setCurrentVariant() to set the current variant");
        return false;
    }
#endif

    struct tc_sha256_state_struct digestSha;

    tc_sha256_init(&digestSha);

    tc_sha256_update(&digestSha, (const uint8_t *)store->imageInfo.signatureInfo.message, strlen(store->imageInfo.signatureInfo.message));

    uint8_t digest[TC_SHA256_DIGEST_SIZE];

    tc_sha256_final(&digestSha, digest);

    uint8_t *signerKey;

    if (0 == strcmp(message->provider, "zodiac"))
    {
        // make sure this provider is allowed to sign given pattern
        if (!isMatch(message->variantPattern, "*")) // zodiac is allowed to sign any variant
        {
            bootLog("ERROR: Image %s is signed by %s but this provider is not permitted to sign this variant pattern (%s)", store->imageInfo.imageName, message->provider, message->variantPattern);
            return false;
        }
        signerKey = zodiacSignerPub;
    }
    else
    {
        bootLog("ERROR: Image %s is signed by unknown provider %s", store->imageInfo.imageName, message->provider);
        return false;
    }

    if (uECC_verify(signerKey, digest, TC_SHA256_DIGEST_SIZE, store->imageInfo.signatureInfo.signature, uECC_secp256r1))
    {
        bootLog("ERROR: Image %s has invalid signature", store->imageInfo.imageName);
        return false;
    }

    if (message->size > store->imageInfo.encryption.encryptedSize)
    {
        bootLog("ERROR: Image %s has invalid size %d; expected less than encrypted size (%d)", store->imageInfo.imageName, store->imageInfo.encryption.encryptedSize, message->size);
        return false;
    }

    return true;
}

static int logStartIndex = 0;
static int logIndex;
static struct FlashDevice *logFlash;

void bootLogInit(struct FlashDevice *flash, uint32_t address)
{
    logFlash = flash;
    logIndex = address;
    logStartIndex = address;

    char buffer[FLASH_BLOCK_SIZE];

    logFlash->read(logIndex, buffer, FLASH_BLOCK_SIZE);

    for (int i = 0; i < FLASH_BLOCK_SIZE; i++)
    {
        if (buffer[i] == 0xFF)
        {
            logIndex += i;
            break;
        }
    }
}

void bootLog(const char *format, ...)
{
    if (logStartIndex == 0)
        return; // not initialized

    if (logIndex - logStartIndex >= (3 * FLASH_BLOCK_SIZE) / 4)
    {
        logFlash->erase(logStartIndex, FLASH_BLOCK_SIZE);
        logIndex = logStartIndex;
    }

    if (logIndex % 4 != 0)
    {
        // make sure our writing is alligned to 4 bytes
        uint8_t j[FLASH_WRITE_ALIGNMENT];

        logFlash->read(logIndex - logIndex % FLASH_WRITE_ALIGNMENT, j, FLASH_WRITE_ALIGNMENT);
        memset(j + logIndex % FLASH_WRITE_ALIGNMENT, 0, FLASH_WRITE_ALIGNMENT - logIndex % FLASH_WRITE_ALIGNMENT);

        int wres = logFlash->write(logIndex - logIndex % FLASH_WRITE_ALIGNMENT, j, FLASH_WRITE_ALIGNMENT);

        logIndex += wres >= 0 ? wres : 0;
    }

    va_list args;
    va_start(args, format);

    char buffer[256];
    memset(buffer, 0x00, sizeof(buffer));

    vsprintf(buffer, format, args);

    va_end(args);

    int wres = logFlash->write(logIndex, buffer, strlen(buffer) + 1);

    logIndex += wres >= 0 ? wres : 0;
}