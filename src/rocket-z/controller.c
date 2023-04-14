#include "controller.h"
#include <stdarg.h>
#include <string.h>

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

void image_setSignature(struct ImageInfo *info, const char *digest, const char *signature)
{
    if (strlen(digest) <= sizeof(info->signatureInfo.digest) - 1)
        strcpy(info->signatureInfo.digest, digest);

    if (strlen(signature) <= sizeof(info->signatureInfo.signature) - 1)
        strcpy(info->signatureInfo.signature, signature);
}

void image_setEncryption(struct ImageInfo *info, const char *pubKey, enum EncryptionMethod method, size_t encryptedSize)
{
    if (strlen(pubKey) <= sizeof(info->encryption.pubKey) - 1)
        strcpy(info->encryption.pubKey, pubKey);

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

static int logStartIndex;
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
    if (logIndex - logStartIndex >= (3 * FLASH_BLOCK_SIZE) / 4)
    {
        logFlash->erase(logStartIndex, FLASH_BLOCK_SIZE);
        logIndex = logStartIndex;
    }

    va_list args;
    va_start(args, format);

    char buffer[256];
    memset(buffer, 0x00, sizeof(buffer));

    vsprintf(buffer, format, args);

    va_end(args);

    logFlash->write(logIndex, buffer, strlen(buffer) + 1);

    logIndex += strlen(buffer) + 1;
}