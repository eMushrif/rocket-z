#include "controller.h"
#include <stdarg.h>
#include <string.h>
#include "keys.h"
#include <zephyr/data/json.h>
#include <zephyr/sys/base64.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/cbc_mode.h>
#include "pem/pem-decode.h"
#include <zephyr/sys/crc.h>

#include "config.h"
#include "boot-log.h"
#include "boot-info-ctrl.h"
#include "bootloader.h"

enum BootError appImage_readHeader(struct AppImageHeader *header, const struct AppImageStore *store)
{
    struct BootFlashDevice *device = bootInfo_getFlashDevice(store->storage);

    int res = device->read(store->startAddr, header, sizeof(struct AppImageHeader));

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    bool isStringsOk = false;

    // make sure strings don't cause issues because of missing null terminator
    for (int i = 0; i < sizeof(struct AppImageHeader); i++)
    {
        if (((uint8_t *)header)[i] != 0xFF)
        {
            isStringsOk = true;
            break;
        }
    }

    if (!isStringsOk)
    {
        bootLog("ERROR: Image header is invalid. Area seems to be erased.", header->headerVersion);
        return BOOT_ERROR_FAILED_PARSE;
    }

    isStringsOk = false;

    // make sure strings don't cause issues because of missing null terminator
    for (int i = sizeof(header->imageName) - 1; i >= 0; i--)
    {
        if (header->imageName[i] == 0)
        {
            isStringsOk = true;
            break;
        }
    }

    if (!isStringsOk)
    {
        bootLog("ERROR: Image header is invalid or version (%d) is not supported; imageName is longer than it should be", header->headerVersion);
        return BOOT_ERROR_TOO_LARGE;
    }

    isStringsOk = false;

    for (int i = sizeof(header->signatureInfo.message) - 1; i >= 0; i--)
    {
        if (header->signatureInfo.message[i] == 0)
        {
            isStringsOk = true;
            break;
        }
    }

    if (!isStringsOk)
    {
        bootLog("ERROR: Image header is invalid or version (%d) is not supported; signature message is longer that it should be", header->headerVersion);
        return BOOT_ERROR_TOO_LARGE;
    }

    // check major version
    if ((uint16_t)header->headerVersion != (uint16_t)IMAGE_HEADER_VERSION_0_0)
    {
        bootLog("WARNING: Image header version (%d) might not be supported", header->headerVersion);
        return BOOT_ERROR_INVALID_HEADER_VERSION;
    }

    return 0;
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

#define DESCR_ARRAY_SIZE 6

struct json_obj_descr descr[DESCR_ARRAY_SIZE] = {
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, authenticator, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, authorId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, time, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, variantPattern, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, size, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct AppImageSignatureMessage, sha256, JSON_TOK_STRING),
};

enum BootError appImage_getSignatureMessage(const struct AppImageHeader *header, struct AppImageSignatureMessage *messageOut, char *messageBuff)
{
    strcpy(messageBuff, header->signatureInfo.message);

    int parseResult = json_obj_parse(messageBuff, strlen(messageBuff), descr, DESCR_ARRAY_SIZE, messageOut);

    if (parseResult < 0)
    {
        bootLog("ERROR: Image %.64s has invalid signature message. Parser returned error %d.", header->imageName, parseResult);
        return BOOT_ERROR_SIGNATURE_MESSAGE_INVALID;
    }

    if (!((parseResult & 0b111111) == 0b111111))
    {
        for (int i = 0; i < DESCR_ARRAY_SIZE; i++)
        {
            if (!(parseResult & (1 << i)))
            {
                bootLog("ERROR: Image %.64s signature message is missing field %.64s", header->imageName, descr[i].field_name);
            }
        }
        bootLog("ERROR: Image %.64s has invalid signature message", header->imageName);
        return BOOT_ERROR_SIGNATURE_MESSAGE_INVALID;
    }

    return BOOT_ERROR_SUCCESS;
}

enum BootError appImage_verifySignature(const struct AppImageHeader *imageInfo)
{
    struct AppImageSignatureMessage messageOut;
    char messageBuff[CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];

    int res = appImage_getSignatureMessage(imageInfo, &messageOut, messageBuff);

    if (res < 0)
    {
        return res;
    }

    uint8_t authenticatorKey[64];
    int len = 0;

    for (int i = 0; i < (BOOT_AUTHENTICATOR_COUNT + 1); i++)
    {
        if (i == BOOT_AUTHENTICATOR_COUNT)
        {
            // Authenticator not found
            bootLog("ERROR: Image %.64s is signed by unknown authenticator %.64s", imageInfo->imageName, messageOut.authenticator);
            return BOOT_ERROR_NO_AUTHENTICATOR;
        }
        else if (0 == strcmp(messageOut.authenticator, bootAuthenticators[i].name))
        {
            // make sure this authenticator is allowed to sign given pattern
            if (!isMatch(messageOut.variantPattern, bootAuthenticators[i].variantPattern)) // zodiac is allowed to sign any variant
            {
                bootLog("ERROR: Image %.64s is signed by %.64s but this authenticator is not expected to sign this variant pattern (%.64s)", imageInfo->imageName, messageOut.authenticator, messageOut.variantPattern);
                continue;
                // return BOOT_ERROR_AUTHENTICATOR_HAS_LIMITED_PERMISSIONS;
            }

            int res = pemExtract(bootAuthenticators[i].pubKey, EC_P256_PUBLIC_KEY, authenticatorKey, &len);

            if (len <= 0)
            {
                bootLog("ERROR: Parsing public key for authenticator %.64s failed. Expecting PEM-formatted prime256v1 string.", messageOut.authenticator);
                continue;
                // return BOOT_ERROR_FAILED_PARSE;
            }

            if (res < 0)
            {
                bootLog("WARNING: Reading public key for %.64s. Expecting PEM-formatted prime2561v1 string. Not sure what the given string is but I'll try it.\n", messageOut.authenticator);
            }

            break;
        }
    }

    struct tc_sha256_state_struct digestSha;

    tc_sha256_init(&digestSha);

    tc_sha256_update(&digestSha, (const uint8_t *)imageInfo->signatureInfo.message, strlen(imageInfo->signatureInfo.message));

    uint8_t digest[TC_SHA256_DIGEST_SIZE];

    tc_sha256_final(digest, &digestSha);

    if (!uECC_verify(authenticatorKey, digest, TC_SHA256_DIGEST_SIZE, imageInfo->signatureInfo.signature, uECC_secp256r1()))
    {
        bootLog("ERROR: Image %.64s has invalid signature", imageInfo->imageName);
        return BOOT_ERROR_INVALID_SIGNATURE;
    }

    return BOOT_ERROR_SUCCESS;
}

enum BootError appImage_verify(const struct AppImageStore *store, const struct BootInfo *bootInfo)
{
    if (!bootInfo_hasImage(store))
    {
        bootLog("ERROR: Store is invalid or does not contain an image");
        return BOOT_ERROR_APP_IMAGE_NOT_VALID;
    }

    // read image header
    struct AppImageHeader header;

    int res = appImage_readHeader(&header, store);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    // check encryption method
    if (header.encryption.method != ENCRYPTION_EC_P256_AES_128_CBC_SHA_256 && header.encryption.method != ENCRYPTION_NONE)
    {
        bootLog("ERROR: Image %.64s is encrypted with method %d which is not supported", header.imageName, header.encryption.method);
        return BOOT_ERROR_UNSUPPORTED_ENCRYPTION_METHOD;
    }

    int sigVer = appImage_verifySignature(&header);

    if (BOOT_ERROR_SUCCESS != sigVer)
    {
        bootLog("ERROR: Failed to verify signature");
        return sigVer;
    }

    struct AppImageSignatureMessage messageOut;
    char messageBuff[CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];

    res = appImage_getSignatureMessage(&header, &messageOut, messageBuff);

    if (res < 0)
    {
        return res;
    }

#if 1 // Checking variant pattern match should be done by the application
    if (NULL != bootInfo && !isMatch(bootInfo->currentVariant, messageOut.variantPattern))
    {
        bootLog("WARNING: Image %.64s is signed for pattern %.64s that doesn't match current variant (%.64s)", header.imageName, messageOut.variantPattern, bootInfo->currentVariant);
        bootLog("HINT: use bootInfo_setCurrentVariant() to set the current variant");
        // return false;
    }
#endif

    // check sha
    size_t len;
    uint8_t sha[TC_SHA256_DIGEST_SIZE];

    res = base64_decode(sha, sizeof(sha), &len, messageOut.sha256, strlen(messageOut.sha256));

    if (res < 0)
    {
        bootLog("ERROR: Image %.64s has invalid sha256. Expecting base-64 encoded hash.", header.imageName);
        return BOOT_ERROR_FAILED_PARSE;
    }

    // verify image size
    if (header.headerSize > store->maxSize)
    {
        bootLog("ERROR: Image header (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.encryption.encryptedSize > store->maxSize)
    {
        bootLog("ERROR: Image data (%d bytes) is too large to fit in a storage of max %d bytes", header.encryption.encryptedSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.headerSize + header.encryption.encryptedSize > store->maxSize)
    {
        bootLog("ERROR: Image (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize + header.encryption.encryptedSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.encryption.encryptedSize == 0)
    {
        bootLog("ERROR: Image %.64s has invalid encrypted data size of %d; expected none-zero value;", header.imageName, messageOut.size, header.encryption.encryptedSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.encryption.method != ENCRYPTION_NONE && header.encryption.encryptedSize % TC_AES_BLOCK_SIZE != 0)
    {
        bootLog("ERROR: Image %.64s has invalid encrypted data size of %d; expected multiple of %d;", header.imageName, messageOut.size, TC_AES_BLOCK_SIZE);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (messageOut.size > header.encryption.encryptedSize)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; expected no more than encrypted size (%d)", header.imageName, messageOut.size, header.encryption.encryptedSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (messageOut.size == 0)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; expected none-zero size.", header.imageName, header.encryption.encryptedSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (messageOut.size > CONFIG_ROCKETZ_MAX_APPIMAGE_SIZE)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; larger than maximum allowed (%d)", header.imageName, messageOut.size, CONFIG_ROCKETZ_MAX_APPIMAGE_SIZE);
        return BOOT_ERROR_INVALID_SIZE;
    }

    return BOOT_ERROR_SUCCESS;
}

struct Secret
{
    uint8_t key[16];
    uint8_t iv[16];
    struct tc_aes_key_sched_struct sched;
};

enum BootError appImage_transfer(const struct AppImageStore *fromStore, struct AppImageStore *toStore, struct BootInfo *bootInfoBuff)
{
    // read image header
    struct AppImageHeader header;

    int res = appImage_readHeader(&header, fromStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    if (header.encryption.encryptedSize > toStore->maxSize || header.encryption.encryptedSize + header.headerSize > toStore->maxSize || header.headerSize > toStore->maxSize)
    {
        bootLog("ERROR: Image %.64s is too large to fit in target storage", header.imageName);
        return BOOT_ERROR_INVALID_SIZE;
    }

    struct Secret secret;

    bool toAppStore = toStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && toStore->startAddr == CONFIG_ROCKETZ_APP_ADDR;
    bool fromAppStore = fromStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && fromStore->startAddr == CONFIG_ROCKETZ_APP_ADDR;

    if (toAppStore || fromAppStore)
    {
        int res = getEncryptionKey(&header, &secret);

        if (res < 0)
        {
            memset(&secret, 0x00, sizeof(secret));
            bootLog("ERROR: Failed to get encryption key for image %.64s", header.imageName);
            return res;
        }
    }

    bootInfo_setHasImage(toStore, false);

    // update imageInfo
    // memcpy(&toStore->imageInfo, &fromStore->imageInfo, sizeof(struct AppImageHeader));

    if (NULL != bootInfoBuff)
        bootInfo_save(bootInfoBuff);

    res = appImage_transfer_(fromStore, toStore, (toAppStore || fromAppStore) ? &secret : NULL);

    memset(&secret, 0x00, sizeof(secret));

    if (res < 0)
    {
        bootLog("ERROR: Failed to transfer image. Error %d.", res);
        return res;
    }

    bootInfo_setHasImage(toStore, bootInfo_hasImage(fromStore));

    if (NULL != bootInfoBuff)
        bootInfo_save(bootInfoBuff);

    return 0;
}

int getEncryptionKey(const struct AppImageHeader *header, struct Secret *secretOut)
{
    uint8_t prv[32];

    struct BootFlashDevice *internalFlash = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH);

    int res = internalFlash->read(CONFIG_ROCKETZ_KEY_ADDR, prv, sizeof(prv));

    if (res < 0)
    {
        // clear prv
        memset(prv, 0x00, sizeof(prv));
        bootLog("ERROR: Failed to read private key. Error %d.", res);
        return res;
    }

    res = uECC_shared_secret(header->encryption.pubKey, prv, (uint8_t *)secretOut, uECC_secp256r1());

    if (0xFF == prv[0])
    {
        bootLog("WARNING: Private key might have not been stored in flash or is erased");
    }

    // clear prv
    memset(prv, 0x00, sizeof(prv));

    if (res != 1)
    {
        // clear secret
        memset(secretOut, 0x00, sizeof(struct Secret));

        bootLog("ERROR: Failed to derive encryption key");

        return BOOT_ERROR_UNKNOWN;
    }

    struct tc_sha256_state_struct digestSha;
    tc_sha256_init(&digestSha);
    tc_sha256_update(&digestSha, (uint8_t *)secretOut, sizeof(secretOut->iv) + sizeof(secretOut->key));
    tc_sha256_final((uint8_t *)secretOut, &digestSha);

    tc_aes128_set_encrypt_key(&secretOut->sched, secretOut->key);

    return 0;
}

int appImage_transfer_(const struct AppImageStore *fromStore, const struct AppImageStore *toStore, const struct Secret *secret)
{
    struct BootFlashDevice *fromDevice = bootInfo_getFlashDevice(fromStore->storage);
    struct BootFlashDevice *toDevice = bootInfo_getFlashDevice(toStore->storage);

    // read image header
    struct AppImageHeader fromHeader;

    int res = appImage_readHeader(&fromHeader, fromStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    // read to header
    struct AppImageHeader toHeader;

    res = appImage_readHeader(&toHeader, toStore);

    if (res < 0)
    {
        // zero all sizes in toHeader, since we couldn't read it
        memset(&toHeader, 0x00, sizeof(toHeader));
    }

    size_t eraseSize = MAX(
        MIN(fromHeader.encryption.encryptedSize + fromHeader.headerSize, fromStore->maxSize),
        MIN(toHeader.encryption.encryptedSize + toHeader.headerSize, toStore->maxSize));

    eraseSize = MIN(eraseSize, CONFIG_ROCKETZ_MAX_APPIMAGE_SIZE);

    bootLog("WARNING: Erasing (at least) %d bytes from destination storage", eraseSize);

    // Erase image area
    res = toDevice->erase(toStore->startAddr, eraseSize);

    if (res < 0)
    {
        bootLog("ERROR: Failed to erase image area. Error %d.", res);
        return res;
    }

    bool toAppStore = toStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && toStore->startAddr == CONFIG_ROCKETZ_APP_ADDR;
    bool fromAppStore = fromStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && fromStore->startAddr == CONFIG_ROCKETZ_APP_ADDR;

    // one buffer for cipher, decipher including iv

    const size_t blockSize = CONFIG_ROCKETZ_FLASH_BLOCK_SIZE;

    uint8_t buff[CONFIG_ROCKETZ_FLASH_BLOCK_SIZE + (2 * TC_AES_BLOCK_SIZE)];

    uint8_t *decipher, *cipher, *_iv;

    if (toAppStore)
    {
        decipher = buff;
        _iv = buff + TC_AES_BLOCK_SIZE;
        cipher = buff + (2 * TC_AES_BLOCK_SIZE);
        memcpy(_iv, secret->iv, TC_AES_BLOCK_SIZE);
    }
    else if (fromAppStore)
    {
        _iv = buff;
        cipher = buff + TC_AES_BLOCK_SIZE; // cipher will have iv prepended
        decipher = buff + (2 * TC_AES_BLOCK_SIZE);
        memcpy(_iv, secret->iv, TC_AES_BLOCK_SIZE);
    }

    // copy image header
    toDevice->write(toStore->startAddr, &fromHeader, fromHeader.headerSize);

    if (toAppStore)
    {
        int i = fromHeader.headerSize;

        for (; i < fromHeader.encryption.encryptedSize + fromHeader.headerSize; i += blockSize)
        {
            bootloader_wdtFeed();

            size_t sizeAct = MIN(blockSize, fromHeader.encryption.encryptedSize + fromHeader.headerSize - i);

            int res = fromDevice->read(fromStore->startAddr + i, cipher, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
                return res;
            }

            if (fromHeader.encryption.method != ENCRYPTION_NONE)
            {
                res = tc_cbc_mode_decrypt(decipher, sizeAct, cipher, sizeAct, _iv, (const TCAesKeySched_t)(&secret->sched));
            }
            else
            {
                res = 1;
                memcpy(decipher, cipher, sizeAct);
            }

            if (res != 1)
            {
                bootLog("ERROR: Failed to decrypt image data. Error %d.", res);
                return BOOT_ERROR_UNKNOWN;
            }

            res = toDevice->write(toStore->startAddr + i, decipher, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to write image data. Error %d.", res);
                return res;
            }

            // copy new initialization vector
            memcpy(_iv, cipher + sizeAct - TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);
        }
    }
    else if (fromAppStore)
    {
        int i = fromHeader.headerSize;

        for (; i < fromHeader.encryption.encryptedSize + fromHeader.headerSize; i += blockSize)
        {
            bootloader_wdtFeed();

            size_t sizeAct = MIN(blockSize, fromHeader.encryption.encryptedSize + fromHeader.headerSize - i);

            int res = fromDevice->read(fromStore->startAddr + i, decipher, sizeAct);
            if (res <= 0)
            {
                bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
                return res;
            }

            if (fromHeader.encryption.method != ENCRYPTION_NONE)
            {
                res = tc_cbc_mode_encrypt(cipher - TC_AES_BLOCK_SIZE /* include prepended iv */, sizeAct + TC_AES_BLOCK_SIZE, decipher, sizeAct, _iv, (const TCAesKeySched_t)(&secret->sched));
            }
            else
            {
                res = 1;
                memcpy(decipher, cipher, sizeAct);
            }

            if (res != 1)
            {
                bootLog("ERROR: Failed to encrypt image data. Error %d.", res);
                return BOOT_ERROR_UNKNOWN;
            }

            res = toDevice->write(toStore->startAddr + i, cipher, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to write image data. Error %d.", res);
                return res;
            }

            // copy new initialization vector
            memcpy(_iv, cipher + sizeAct - TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);
        }
    }
    else
    {
        int i = fromHeader.headerSize;

        for (; i < fromHeader.encryption.encryptedSize + fromHeader.headerSize; i += blockSize)
        {
            bootloader_wdtFeed();

            size_t sizeAct = MIN(blockSize, fromHeader.encryption.encryptedSize + fromHeader.headerSize - i);

            int res = fromDevice->read(fromStore->startAddr + i, buff, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to read image data from storage");
                return res;
            }

            res = toDevice->write(toStore->startAddr + i, buff, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to write image data");
                return res;
            }
        }
    }

    return 0;
}

enum BootError appImage_verifyChecksum(const struct AppImageStore *store)
{
    bool isLoadedApp = store->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && store->startAddr == CONFIG_ROCKETZ_APP_ADDR;

    // get signature message
    struct AppImageSignatureMessage messageOut;

    // read image header
    struct AppImageHeader header;

    int res = appImage_readHeader(&header, store);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    bool isEncrypted = !isLoadedApp && header.encryption.method != ENCRYPTION_NONE;

    if (header.headerSize > store->maxSize)
    {
        bootLog("ERROR: Image header (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.encryption.encryptedSize > store->maxSize)
    {
        bootLog("ERROR: Image data (%d bytes) is too large to fit in a storage of max %d bytes", header.encryption.encryptedSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (header.headerSize + header.encryption.encryptedSize > store->maxSize)
    {
        bootLog("ERROR: Image (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize + header.encryption.encryptedSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    res = appImage_getSignatureMessage(&header, &messageOut, header.signatureInfo.message);

    if (res < 0)
    {
        return res;
    }

    // decode sha256 from base 64
    uint8_t sha256[TC_SHA256_DIGEST_SIZE];
    size_t len;
    res = base64_decode(sha256, TC_SHA256_DIGEST_SIZE, &len, messageOut.sha256, strlen(messageOut.sha256));

    if (res < 0)
    {
        bootLog("ERROR: Failed to decode sha256 from base64. Error %d.", res);
        return res;
    }

    // initiate sha256
    struct tc_sha256_state_struct sha256State;
    res = tc_sha256_init(&sha256State);

    // block buffer
    uint8_t buff[CONFIG_ROCKETZ_FLASH_BLOCK_SIZE + (2 * TC_AES_BLOCK_SIZE)];

    struct Secret secret;

    if (isEncrypted)
    {
        // drive encryption key and iv
        res = getEncryptionKey(&header, &secret);

        if (res < 0)
        {
            memset(&secret, 0, sizeof(secret));
            bootLog("ERROR: Failed to get encryption key.");
            return res;
        }
    }

    struct BootFlashDevice *device = bootInfo_getFlashDevice(store->storage);

    uint8_t *decipher, *cipher, *_iv;

    decipher = buff;
    _iv = buff + TC_AES_BLOCK_SIZE;
    cipher = buff + (2 * TC_AES_BLOCK_SIZE);
    memcpy(_iv, secret.iv, TC_AES_BLOCK_SIZE);

    for (int i = 0; i < header.encryption.encryptedSize; i += CONFIG_ROCKETZ_FLASH_BLOCK_SIZE)
    {
        bootloader_wdtFeed();

        size_t sizeEncrypted = MIN(CONFIG_ROCKETZ_FLASH_BLOCK_SIZE, header.encryption.encryptedSize - i);
        size_t sizeData = MIN(CONFIG_ROCKETZ_FLASH_BLOCK_SIZE, messageOut.size - i);

        res = device->read(store->startAddr + header.headerSize + i, cipher, sizeEncrypted);

        if (res <= 0)
        {
            memset(&secret, 0, sizeof(secret));
            bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
            return res;
        }

        if (isEncrypted)
        {
            res = tc_cbc_mode_decrypt(decipher, sizeEncrypted, cipher, sizeEncrypted, _iv, &secret.sched);

            if (res != 1)
            {
                memset(&secret, 0, sizeof(secret));
                bootLog("ERROR: Failed to decrypt image data. Error %d.", res);
                return BOOT_ERROR_UNKNOWN;
            }
        }

        res = tc_sha256_update(&sha256State, isEncrypted ? decipher : cipher, sizeData);

        // copy new initialization vector
        memcpy(_iv, cipher + sizeEncrypted - TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);
    }

    memset(&secret, 0, sizeof(secret));

    // get final sha256
    uint8_t sha256Final[TC_SHA256_DIGEST_SIZE];
    tc_sha256_final(sha256Final, &sha256State);

    // compare sha256
    if (memcmp(sha256, sha256Final, TC_SHA256_DIGEST_SIZE) != 0)
    {
        // check if the Rocket public key is the same as the one used to encrypt the image
        uint8_t pub[64];

        int len = 0;
        pemExtract(rocketPubKey, EC_P256_PUBLIC_KEY, pub, &len);

        if (len > 0)
        {
            // apply check
            uint32_t res = crc32_ieee(pub, sizeof(pub));
            if (res != header.encryption.pubKeyCrc32)
            {
                bootLog("WARNING: Encryption key was possibly generated with a public key other than the one assigned to this bootloader. Expected CRC32 0x%08x but got 0x%08x", res, header.encryption.pubKeyCrc32);
            }
        }

        bootLog("ERROR: Image checksum failed.");

        return BOOT_ERROR_FAILED_CHECKSUM;
    }

    return 0;
}