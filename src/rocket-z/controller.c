#include "controller.h"
#include <stdarg.h>
#include <string.h>

struct BootInfo *bootInfo_load(uint32_t address)
{
    struct BootInfo *result = (struct BootInfo *)malloc(2 * sizeof(struct BootInfo));

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, result, sizeof(struct BootInfo));

    if (result->version != BOOT_VERSION_0_0)
    {
        // Boot information not loaded, or different version. Reset info.
        memset(result, 0, sizeof(struct BootInfo));

        // set bootloader name
        strcpy(result->bootloaderName, "rocket-z");

        // set boot version
        result->version = BOOT_VERSION_0_0;

        // reset image status
        for (int i = 0; i < 2; i++)
        {
            result->img[i].status = -1;
            image_setFlag(&result->img[i], BOOT_IMG_INVALID);
        }
    }

    // copy the original boot info to the second half of the buffer
    memcpy(result, result + sizeof(struct BootInfo), sizeof(struct BootInfo));

    return result;
}

void bootInfo_save(uint32_t address, const struct BootInfo *info)
{
    // if info is the same as the one in flash, don't write it
    if (memcmp(info + sizeof(struct BootInfo), info, sizeof(struct BootInfo)) == 0)
        return;

    // if any bits were changed from 0 to 1, erase the flash page
    for (int i = 0; i < sizeof(struct BootInfo); i++)
    {
        if (((uint8_t *)info)[i] & ~((uint8_t *)info + sizeof(struct BootInfo))[i])
        {
            bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, sizeof(struct BootInfo));
            break;
        }
    }

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));
}

void image_setName(struct ImageInfo *info, const char *name)
{
    strcpy(info->imageId, name);

    // invalidate the image
    image_setFlag(info, BOOT_IMG_INVALID);
}

void image_setAddress(struct ImageInfo *info, size_t address, enum ImageStorage storage)
{
    info->startAddr = address;
    info->storage = storage;

    // invalidate the image
    image_setFlag(info, BOOT_IMG_INVALID);
}

void image_setSignature(struct ImageInfo *info, const char *digest, const char *signature)
{
    strcpy(info->signatureInfo.digest, digest);
    strcpy(info->signatureInfo.signature, signature);

    // invalidate the image
    image_setFlag(info, BOOT_IMG_INVALID);
}

void image_setEncryption(struct ImageInfo *info, const char *pubKey, enum EncryptionMethod method, size_t encryptedSize)
{
    strcpy(info->encryption.pubKey, pubKey);
    info->encryption.method = method;
    info->encryption.encryptedSize = encryptedSize;

    // invalidate the image
    image_setFlag(info, BOOT_IMG_INVALID);
}

bool image_getFlag(const struct ImageInfo *info, enum ImageStatus flag)
{
    return (info->status & ~(flag)) == flag;
}

void image_setFlag(struct ImageInfo *info, enum ImageStatus flag)
{
    switch (flag)
    {
    case BOOT_IMG_REQUESTED:
        info->status |= (-1) & ~(BOOT_IMG_INVALID);

    default:
        info->status &= ~(flag);
        break;
    }
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