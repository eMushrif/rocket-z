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

struct BootInfo *bootInfo_load(uint32_t address, struct BootInfoBuffer *info)
{
    struct BootInfo *result = info;

    if (NULL == result)
        return NULL;

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, result, sizeof(struct BootInfo));

    if (result->version != BOOT_VERSION_0_0)
    {
        // Boot information not loaded, or different version. Reset info.
        memset(result, 0, sizeof(struct BootInfo));

        // set bootloader name
        strcpy(result->bootloaderName, "rocket-zn");

        // set boot version
        result->version = BOOT_VERSION_0_0;
    }

    // make sure appStore parameters are not changed
    appImage_setStore(&result->appStore, BOOT_IMG_STORAGE_INTERNAL_FLASH, ROCKETZ_APP_ADDR, ROCKETZ_MAX_APPIMAGE_SIZE);

    // copy the original boot info to the second half of the buffer
    memcpy(&info->bootInfo_orig, &info->bootInfo, sizeof(struct BootInfo));

    bootInfo_save(address, result);

    return result;
}

void bootInfo_save(uint32_t address, const struct BootInfoBuffer *info)
{
    const struct BootInfoBuffer *buffer = (const struct BootInfoBuffer *)info;

    // if info is the same as the one in flash, don't write it
    if (memcmp(&buffer->bootInfo, &buffer->bootInfo_orig, sizeof(struct BootInfo)) == 0)
        return;

    // if any bits were changed from 0 to 1, erase the flash page
    for (int i = 0; i < sizeof(struct BootInfo); i++)
    {
        if (((uint8_t *)&buffer->bootInfo)[i] & ~((uint8_t *)&buffer->bootInfo_orig)[i])
        {
            bootLog("INFO: Erasing boot info for rewrite");
            bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, ROCKETZ_FLASH_BLOCK_SIZE);
            break;
        }
    }

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));

    // double check that the write was successful
    // copy the updated boot info to the second half of the buffer
    memcpy((struct BootInfo *)(&buffer->bootInfo_orig), &buffer->bootInfo, sizeof(struct BootInfo));

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, (&buffer->bootInfo), sizeof(struct BootInfo));
    if (memcmp(&buffer->bootInfo_orig, &buffer->bootInfo, sizeof(struct BootInfo)) != 0)
    {
        // data wasn't written correctly. erase and write again
        bootLog("INFO: Erasing boot info for rewrite");
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, sizeof(struct BootInfo));
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));
    }
}

int appImage_readHeader(struct AppImageHeader *header, const struct AppImageStore *store)
{
    struct FlashDevice *device = bootInfo_getFlashDevice(store->storage);

    int res = device->read(store->startAddr, header, sizeof(struct AppImageHeader));

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    if (header->headerVersion != IMAGE_HEADER_VERSION_0_0)
    {
        bootLog("ERROR: Image header is invalid or version (%d) is not supported", header->headerVersion);
        return BOOT_ERROR_INVALID_HEADER_VERSION;
    }

    return 0;
}

void appImage_setName(struct AppImageHeader *header, const char *name)
{
    header->headerVersion = IMAGE_HEADER_VERSION_0_0;
    header->headerSize = sizeof(struct AppImageHeader);

    if (strlen(name) <= sizeof(header->imageName) - 1)
        strcpy(header->imageName, name);
}

void appImage_setStorage(struct AppImageStore *info, size_t address, enum AppImageStorage storage, size_t maxSize)
{
    info->startAddr = address;
    info->storage = storage;
}

enum BootError appImage_setSignature(struct AppImageHeader *header, const char *message, const char *signature)
{
    header->headerVersion = IMAGE_HEADER_VERSION_0_0;
    header->headerSize = sizeof(struct AppImageHeader);

    if (strlen(message) <= sizeof(header->signatureInfo.message) - 1)
        strcpy(header->signatureInfo.message, message);

    int len = 0;
    int res = pemExtract(signature, EC_P256_SIGNATURE, header->signatureInfo.signature, &len);

    if (0 == len)
    {
        bootLog("ERROR: Setting signature for %.64s. Failed to parse argument. Expecting PEM-formatted prime2561v1 signature.", header->imageName);
        return BOOT_ERROR_FAILED_PARSE;
    }

    if (res < 0)
    {
        bootLog("WARNING: Setting signature for %.64s. Expecting PEM-formatted prime2561v1 signature. Not sure what the given signature is but I'll try it.\n", header->imageName);
    }

    return BOOT_ERROR_SUCCESS;
}

enum BootError appImage_setEncryption(struct AppImageHeader *header, const char *pubKey, enum AppImageEncryptionMethod method, size_t encryptedSize)
{
    header->headerVersion = IMAGE_HEADER_VERSION_0_0;
    header->headerSize = sizeof(struct AppImageHeader);

    int len = 0;
    int res = pemExtract(pubKey, EC_P256_PUBLIC_KEY, header->encryption.pubKey, &len);

    if (0 == len)
    {
        bootLog("ERROR: Setting encryption key for %.64s. Failed to parse argument. Expecting PEM-formatted prime2561v1 public key.", header->imageName);
        return BOOT_ERROR_FAILED_PARSE;
    }

    if (res < 0)
    {
        bootLog("WARNING: Setting encryption key for %.64s. Expecting PEM-formatted prime2561v1 public key. Not sure what the given key is but I'll try it.\n", header->imageName);
    }

    header->encryption.method = method;
    header->encryption.encryptedSize = encryptedSize;

    return 0;
}

void appImage_setValid(struct AppImageStore *info, bool valid)
{
    info->isValid = BOOT_IMG_STORE_VALID;
}

bool appImage_isValid(struct AppImageStore *info)
{
    return info->isValid == BOOT_IMG_STORE_VALID;
}

void bootInfo_setCurrentVariant(struct BootInfo *info, const char *variant)
{
    if (strlen(variant) <= sizeof(info->currentVariant) - 1)
        strcpy(info->currentVariant, variant);
}

void appImage_setLoadRequest(struct AppImageStore *store)
{
    if (0 == store->loadRequests)
    {
        store->loadRequests = -1;
    }

    for (int i = 0; i < 8 * sizeof(store->loadRequests); i++)
    {
        if ((1 << i) & store->loadRequests)
        {
            store->loadRequests &= ~(1 << i);
            return;
        }
    }
}

void appImage_clearLoadRequest(struct AppImageStore *store)
{
    store->loadAttempts = store->loadRequests;
}

bool appImage_hasLoadRequest(const struct AppImageStore *store)
{
    return store->loadRequests != store->loadAttempts;
}

bool appImage_isCurrent(const struct AppImageHeader *header, const struct BootInfo *bootInfo)
{
    struct AppImageHeader appHeader;

    int res = appImage_readHeader(&appHeader, &bootInfo->appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read app image header. Error %d.", res);
        return res;
    }

    return 0 == memcmp(&appHeader.signatureInfo, &header->signatureInfo, sizeof(appHeader.signatureInfo));
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

int appImage_getSignatureMessage(const struct AppImageHeader *header, struct SignatureMessage *messageOut, char *messageBuff)
{
    strcpy(messageBuff, header->signatureInfo.message);

    int parseResult = json_obj_parse(messageBuff, strlen(messageBuff), descr, DESCR_ARRAY_SIZE, messageOut);

    if (parseResult < 0)
    {
        bootLog("ERROR: Image %.64s has invalid signature message. Parser returned error %d.", header->imageName, parseResult);
        return BOOT_ERROR_SIGNATURE_MESSAGE_INVALID;
    }

    if (!((parseResult & 127) == 127))
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

    return 0;
}

int appImage_verifySignature(const struct AppImageHeader *imageInfo)
{
    struct SignatureMessage messageOut;
    char messageBuff[ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];

    int res = appImage_getSignatureMessage(imageInfo, &messageOut, messageBuff);

    if (res < 0)
    {
        return res;
    }

    uint8_t signerKey[64];
    int len = 0;

    if (0 == strcmp(messageOut.provider, "zodiac"))
    {
        // make sure this provider is allowed to sign given pattern
        if (!isMatch(messageOut.variantPattern, "*")) // zodiac is allowed to sign any variant
        {
            bootLog("ERROR: Image %.64s is signed by %.64s but this provider is not expected to sign this variant pattern (%.64s)", imageInfo->imageName, messageOut.provider, messageOut.variantPattern);
            return BOOT_ERROR_SIGNER_HAS_LIMITED_PERMISSIONS;
        }

        int res = pemExtract(zodiacSignerPub, EC_P256_PUBLIC_KEY, signerKey, &len);

        if (len <= 0)
        {
            bootLog("ERROR: Parsing public key for signer %.64s failed. Expecting PEM-formatted prime256v1 string.", messageOut.provider);
            return BOOT_ERROR_FAILED_PARSE;
        }

        if (res < 0)
        {
            bootLog("WARNING: Reading public key for %.64s. Expecting PEM-formatted prime2561v1 string. Not sure what the given string is but I'll try it.\n", messageOut.provider);
        }
    }
    else
    {
        bootLog("ERROR: Image %.64s is signed by unknown provider %.64s", imageInfo->imageName, messageOut.provider);
        return false;
    }

    struct tc_sha256_state_struct digestSha;

    tc_sha256_init(&digestSha);

    tc_sha256_update(&digestSha, (const uint8_t *)imageInfo->signatureInfo.message, strlen(imageInfo->signatureInfo.message));

    uint8_t digest[TC_SHA256_DIGEST_SIZE];

    tc_sha256_final(digest, &digestSha);

    if (!uECC_verify(signerKey, digest, TC_SHA256_DIGEST_SIZE, imageInfo->signatureInfo.signature, uECC_secp256r1()))
    {
        bootLog("ERROR: Image %.64s has invalid signature", imageInfo->imageName);
        return BOOT_ERROR_INVALID_SIGNATURE;
    }

    return BOOT_ERROR_SUCCESS;
}

int appImage_verify(const struct AppImageStore *store, const struct BootInfo *bootInfo)
{
    if (!store->isValid)
    {
        bootLog("ERROR: Store is marked not valid");
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
    if (header.encryption.method != ENCRYPTION_EC_P256_AES_128_CBC_SHA_256)
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

    struct SignatureMessage messageOut;
    char messageBuff[ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];

    res = appImage_getSignatureMessage(&header, &messageOut, messageBuff);

    if (res < 0)
    {
        return res;
    }

#if 1 // Checking variant pattern match should be done by the application
    if (!isMatch(bootInfo->currentVariant, messageOut.variantPattern))
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

    if (header.headerSize + header.encryption.encryptedSize > store->maxSize)
    {
        bootLog("ERROR: Image (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize + header.encryption.encryptedSize, store->maxSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if ((messageOut.size > header.encryption.encryptedSize) && header.encryption.encryptedSize > 0)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; expected no more than encrypted size (%d)", header.imageName, messageOut.size, header.encryption.encryptedSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (messageOut.size == 0)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; expected none-zero size.", header.imageName, header.encryption.encryptedSize);
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (messageOut.size > ROCKETZ_MAX_APPIMAGE_SIZE)
    {
        bootLog("ERROR: Image %.64s has invalid size of %d; larger than maximum allowed (%d)", header.imageName, messageOut.size, ROCKETZ_MAX_APPIMAGE_SIZE);
        return BOOT_ERROR_INVALID_SIZE;
    }

    return BOOT_ERROR_SUCCESS;
}

static int logStartIndex = 0;
static int logIndex;
static const struct FlashDevice *logFlash;

void bootLogInit(const struct FlashDevice *flash, uint32_t address)
{
    logFlash = flash;
    logIndex = address;
    logStartIndex = address;

    char buffer[ROCKETZ_FLASH_BLOCK_SIZE];

    logFlash->read(logIndex, buffer, ROCKETZ_FLASH_BLOCK_SIZE);

    for (int i = 0; i < ROCKETZ_FLASH_BLOCK_SIZE; i++)
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

    if (logIndex - logStartIndex >= (3 * ROCKETZ_FLASH_BLOCK_SIZE) / 4)
    {
        logFlash->erase(logStartIndex, ROCKETZ_FLASH_BLOCK_SIZE);
        logIndex = logStartIndex;
    }

    if (logIndex % 4 != 0)
    {
        // make sure our writing is alligned to 4 bytes
        uint8_t j[ROCKETZ_FLASH_WRITE_ALIGNMENT];

        logFlash->read(logIndex - logIndex % ROCKETZ_FLASH_WRITE_ALIGNMENT, j, ROCKETZ_FLASH_WRITE_ALIGNMENT);
        memset(j + logIndex % ROCKETZ_FLASH_WRITE_ALIGNMENT, 0, ROCKETZ_FLASH_WRITE_ALIGNMENT - logIndex % ROCKETZ_FLASH_WRITE_ALIGNMENT);

        int wres = logFlash->write(logIndex - logIndex % ROCKETZ_FLASH_WRITE_ALIGNMENT, j, ROCKETZ_FLASH_WRITE_ALIGNMENT);

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

void appImage_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize)
{
    info->storage = storage;
    info->startAddr = offset;
    info->maxSize = maxSize;
}

struct Secret
{
    uint8_t key[16];
    uint8_t iv[16];
    struct tc_aes_key_sched_struct sched;
};

int appImage_transfer(const struct AppImageStore *fromStore, struct AppImageStore *toStore, struct BootInfo *bootInfo)
{
    // read image header
    struct AppImageHeader header;

    int res = appImage_readHeader(&header, fromStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    if (header.encryption.encryptedSize > toStore->maxSize)
    {
        bootLog("ERROR: Image %.64s is too large to fit in storage", header.imageName);
        return BOOT_ERROR_INVALID_SIZE;
    }

    struct Secret secret;

    bool toAppStore = toStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && toStore->startAddr == ROCKETZ_APP_ADDR;
    bool fromAppStore = fromStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && fromStore->startAddr == ROCKETZ_APP_ADDR;

    if (toAppStore || fromAppStore)
    {
        int res = getEncryptionKey(&header, &secret);

        if (res < 0)
        {
            bootLog("ERROR: Failed to get encryption key for image %.64s", header.imageName);
            return res;
        }
    }

    appImage_setValid(toStore, false);

    // update imageInfo
    // memcpy(&toStore->imageInfo, &fromStore->imageInfo, sizeof(struct AppImageHeader));

    if (NULL != bootInfo)
        bootInfo_save(ROCKETZ_INFO_ADDR, bootInfo);

    res = appImage_transfer_(fromStore, toStore, (toAppStore || fromAppStore) ? &secret : NULL);

    memset(&secret, 0x00, sizeof(secret));

    if (res < 0)
    {
        bootLog("ERROR: Failed to transfer image. Error %d.", res);
        return res;
    }

    appImage_setValid(toStore, fromStore->isValid);

    return 0;
}

int getEncryptionKey(const struct AppImageHeader *header, struct Secret *secretOut)
{
    uint8_t prv[32];

    struct FlashDevice *internalFlash = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH);

    int res = internalFlash->read(ROCKETZ_KEY_ADDR, prv, sizeof(prv));

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

        return -1;
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
    struct FlashDevice *fromDevice = bootInfo_getFlashDevice(fromStore->storage);
    struct FlashDevice *toDevice = bootInfo_getFlashDevice(toStore->storage);

    // read image header
    struct AppImageHeader fromHeader;

    int res = appImage_readHeader(&fromHeader, fromStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    if (fromHeader.headerSize > toStore->maxSize)
    {
        bootLog("ERROR: Image header is too large to fit in storage");
        return BOOT_ERROR_INVALID_SIZE;
    }

    if (fromHeader.headerSize + fromHeader.encryption.encryptedSize > toStore->maxSize)
    {
        bootLog("ERROR: Image is too large to fit in destination storage");
        return BOOT_ERROR_INVALID_SIZE;
    }

    // read to header
    struct AppImageHeader toHeader;

    res = appImage_readHeader(&toHeader, toStore);

    if (res < 0 && BOOT_ERROR_INVALID_HEADER_VERSION != res)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    size_t eraseSize = MAX(
        MIN(fromHeader.encryption.encryptedSize + fromHeader.headerSize, fromStore->maxSize),
        MIN(toHeader.encryption.encryptedSize + toHeader.headerSize, toStore->maxSize));

    eraseSize = MIN(eraseSize, ROCKETZ_MAX_APPIMAGE_SIZE);

    bootLog("WARNING: Erasing %d bytes from destination storage", eraseSize);

    // Erase image area
    res = toDevice->erase(toStore->startAddr, eraseSize);

    if (res < 0)
    {
        bootLog("ERROR: Failed to erase image area. Error %d.", res);
        return res;
    }

    bool toAppStore = toStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && toStore->startAddr == ROCKETZ_APP_ADDR;
    bool fromAppStore = fromStore->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && fromStore->startAddr == ROCKETZ_APP_ADDR;

    struct SignatureMessage messageOut;
    char messageBuff[ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];

    if (NULL != secret && (toAppStore || fromAppStore))
    {
        int res = appImage_getSignatureMessage((toAppStore ? &fromHeader : &toHeader), &messageOut, messageBuff);

        if (res < 0)
        {
            return res;
        }
    }

    // one buffer for cipher, decipher including iv

    const size_t blockSize = ROCKETZ_FLASH_BLOCK_SIZE;

    uint8_t buff[ROCKETZ_FLASH_BLOCK_SIZE + (2 * TC_AES_BLOCK_SIZE)];

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
            size_t sizeAct = MIN(blockSize, fromHeader.encryption.encryptedSize + fromHeader.headerSize - i);

            int res = fromDevice->read(fromStore->startAddr + i, cipher, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
                return res;
            }

            res = tc_cbc_mode_decrypt(decipher, sizeAct, cipher, sizeAct, _iv, (const TCAesKeySched_t)(&secret->sched));

            if (res != 1)
            {
                bootLog("ERROR: Failed to decrypt image data. Error %d.", res);
                return -1;
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
            size_t sizeAct = MIN(blockSize, fromHeader.encryption.encryptedSize + fromHeader.headerSize - i);

            int res = fromDevice->read(fromStore->startAddr + i, decipher, sizeAct);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
                return res;
            }

            res = tc_cbc_mode_encrypt(cipher - TC_AES_BLOCK_SIZE /* include prepended iv */, sizeAct + TC_AES_BLOCK_SIZE, decipher, sizeAct, _iv, (const TCAesKeySched_t)(&secret->sched));

            if (res != 1)
            {
                bootLog("ERROR: Failed to encrypt image data. Error %d.", res);
                return -1;
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

int appImage_verifyChecksum(const struct AppImageStore *store)
{
    bool isLoadedApp = store->storage == BOOT_IMG_STORAGE_INTERNAL_FLASH && store->startAddr == ROCKETZ_APP_ADDR;

    // get signature message
    struct SignatureMessage messageOut;

    // read image header
    struct AppImageHeader header;

    int res = appImage_readHeader(&header, store);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header. Error %d.", res);
        return res;
    }

    if (header.headerSize > store->maxSize)
    {
        bootLog("ERROR: Image header (%d bytes) is too large to fit in a storage of max %d bytes", header.headerSize, store->maxSize);
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
    uint8_t buff[ROCKETZ_FLASH_BLOCK_SIZE + (2 * TC_AES_BLOCK_SIZE)];

    struct Secret secret;

    if (!isLoadedApp)
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

    struct FlashDevice *device = bootInfo_getFlashDevice(store->storage);

    uint8_t *decipher, *cipher, *_iv;

    decipher = buff;
    _iv = buff + TC_AES_BLOCK_SIZE;
    cipher = buff + (2 * TC_AES_BLOCK_SIZE);
    memcpy(_iv, secret.iv, TC_AES_BLOCK_SIZE);

    // uint8_t *data = (!isLoadedApp) ? decipher : (uint8_t *)store->startAddr;

    for (int i = 0; i < header.encryption.encryptedSize; i += ROCKETZ_FLASH_BLOCK_SIZE)
    {
        size_t sizeEncrypted = MIN(ROCKETZ_FLASH_BLOCK_SIZE, header.encryption.encryptedSize - i);
        size_t sizeData = MIN(ROCKETZ_FLASH_BLOCK_SIZE, messageOut.size - i);

        res = device->read(store->startAddr + header.headerSize + i, cipher, sizeEncrypted);

        if (res <= 0)
        {
            memset(&secret, 0, sizeof(secret));
            bootLog("ERROR: Failed to read image data from storage. Error %d.", res);
            return res;
        }

        if (!isLoadedApp)
        {
            res = tc_cbc_mode_decrypt(decipher, sizeEncrypted, cipher, sizeEncrypted, _iv, &secret.sched);

            if (res != 1)
            {
                memset(&secret, 0, sizeof(secret));
                bootLog("ERROR: Failed to decrypt image data. Error %d.", res);
                return -1;
            }
        }

        res = tc_sha256_update(&sha256State, isLoadedApp ? cipher : decipher, sizeData);

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
        bootLog("ERROR: Image checksum failed.");
        return BOOT_ERROR_FAILED_CHECKSUM;
    }

    return 0;
}

uint32_t bootInfo_getFailCount(const struct BootInfo *info)
{
    int count = 0, countC = 0;

    for (int i = 0; i < sizeof(info->failFlags) * 8; i++)
    {
        if ((~info->failFlags) & (1 << i))
        {
            count++;
        }
    }

    for (int i = 0; i < sizeof(info->failClears) * 8; i++)
    {
        if ((~info->failFlags) & (1 << i))
        {
            countC++;
        }
    }

    return count > countC ? count - countC : 0;
}

void bootInfo_failFlag(struct BootInfo *info)
{
    int currentFailCount = bootInfo_getFailCount(info);

    if (currentFailCount > sizeof(info->failFlags) * 8)
    {
        currentFailCount = sizeof(info->failFlags) * 8;
    }

    if (0 == info->failFlags)
    {
        // all flags are set
        memset(&info->failFlags, 0xFF, sizeof(info->failFlags));

        for (int i = 0; i < currentFailCount; i++)
        {
            info->failFlags &= ~(1 << i);
        }
    }

    // find a set bit and clear it
    for (int i = 0; i < sizeof(info->failFlags) * 8; i++)
    {
        if ((~info->failFlags) & (1 << i))
        {
            info->failFlags &= ~(1 << i);
            break;
        }
    }
}

void bootInfo_failClear(struct BootInfo *info)
{
    info->failClears = info->failFlags;
}