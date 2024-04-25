#include "config.h"
#include "boot-info-ctrl.h"
#include "controller.h"
#include <string.h>
#include "boot-log.h"

int unknownFlashRead(size_t address, void *data, size_t size)
{
    bootLog("ERROR: Unknown flash device identifier");
    return BOOT_ERROR_UNKNOWN_DEVICE;
}

int unknownFlashErase(size_t address, size_t size)
{
    bootLog("ERROR: Unknown flash device identifier");
    return BOOT_ERROR_UNKNOWN_DEVICE;
}

int unknownFlashWrite(size_t address, const void *data, size_t size)
{
    bootLog("ERROR: Unknown flash device identifier");
    return BOOT_ERROR_UNKNOWN_DEVICE;
}

int unknownFlashLock(size_t address, size_t size, enum BootFlashLockType lockType)
{
    bootLog("ERROR: Unknown flash device identifier");
    return BOOT_ERROR_UNKNOWN_DEVICE;
}

struct BootFlashDevice flashDevice_unknown = {
    .read = unknownFlashRead,
    .erase = unknownFlashErase,
    .write = unknownFlashWrite,
    .lock = unknownFlashLock,
};

struct BootInfo *bootInfo_load(struct BootInfo *buff)
{
    struct BootInfo *info = buff;

    if (NULL == info)
        return NULL;

    int res = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(CONFIG_ROCKETZ_INFO_ADDR, info, sizeof(struct BootInfo));

    if (res < 0)
    {
        bootLog("ERROR: Failed to read boot info from flash");
        return NULL;
    }

    return info;
}

enum BootError bootInfo_init(struct BootInfo *info)
{
    if (info->version != BOOT_VERSION_0_0)
    {
        // Boot information not loaded, or different version. Reset info.
        memset(info, 0, sizeof(struct BootInfo));

        // set bootloader name
        strcpy(info->bootloaderName, "rocket-zn");

        // set boot version
        info->version = BOOT_VERSION_0_0;
        info->rollbackImageIndex = -1;
        info->wdtChannelCount = 0;

        info->appStore.storage = BOOT_IMG_STORAGE_INTERNAL_FLASH;
        info->appStore.startAddr = CONFIG_ROCKETZ_APP_ADDR;
        info->appStore.maxSize = CONFIG_ROCKETZ_MAX_APPIMAGE_SIZE;
    }

    // make sure appStore parameters are not changed
    bootInfo_setStore(&info->appStore, BOOT_IMG_STORAGE_INTERNAL_FLASH, CONFIG_ROCKETZ_APP_ADDR, CONFIG_ROCKETZ_MAX_APPIMAGE_SIZE);

    return BOOT_ERROR_SUCCESS;
}

enum BootError bootInfo_save(const struct BootInfo *info)
{
    const struct BootInfo *buffer = info;

    const struct BootInfo buffer_original;

    const uint8_t *address = CONFIG_ROCKETZ_INFO_ADDR;

    bootInfo_load(&buffer_original);

    // if info is the same as the one in flash, don't write it
    if (memcmp(buffer, &buffer_original, sizeof(struct BootInfo)) == 0)
        return BOOT_ERROR_SUCCESS;

    // if any bits were changed from 0 to 1, erase the flash page
    for (int i = 0; i < sizeof(struct BootInfo); i++)
    {
        if (((uint8_t *)buffer)[i] & ~((uint8_t *)&buffer_original)[i])
        {
            bootLog("INFO: Erasing boot info for rewrite");
            bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, CONFIG_ROCKETZ_FLASH_BLOCK_SIZE);
            break;
        }
    }

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));

    // double check that the write was successful

    bootInfo_load(&buffer_original);

    if (memcmp(&buffer_original, buffer, sizeof(struct BootInfo)) != 0)
    {
        // data wasn't written correctly. erase and write again
        bootLog("INFO: Erasing boot info for rewrite");
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, sizeof(struct BootInfo));
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));
    }
    else
    {
        return BOOT_ERROR_SUCCESS;
    }

    bootInfo_load(&buffer_original);

    if (memcmp(&buffer_original, buffer, sizeof(struct BootInfo)) != 0)
    {
        return BOOT_ERROR_UNKNOWN;
    }

    return BOOT_ERROR_SUCCESS;
}

void bootInfo_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize)
{
    info->storage = storage;
    info->startAddr = offset;
    info->maxSize = maxSize;
}

void bootInfo_setHasImage(struct AppImageStore *info, bool valid)
{
    info->hasImage = valid ? BOOT_IMG_STORE_VALID : 0;
}

bool bootInfo_hasImage(const struct AppImageStore *info)
{
    return info->hasImage == BOOT_IMG_STORE_VALID;
}

enum BootError bootInfo_setCurrentVariant(struct BootInfo *info, const char *variant)
{
    if (strlen(variant) <= sizeof(info->currentVariant) - 1)
        strcpy(info->currentVariant, variant);
    else
        return BOOT_ERROR_TOO_LARGE;

    return BOOT_ERROR_SUCCESS;
}

void bootInfo_setLoadRequest(struct AppImageStore *store)
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

    return;
}

void bootInfo_clearLoadRequest(struct AppImageStore *store)
{
    store->loadAttempts = store->loadRequests;
}

bool bootInfo_hasLoadRequest(const struct AppImageStore *store)
{
    return store->loadRequests != store->loadAttempts;
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

        if ((~info->failClears) & (1 << i))
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
        memset(&info->failClears, 0xFF, sizeof(info->failFlags));

        for (int i = 0; i < currentFailCount; i++)
        {
            info->failFlags &= ~(1 << i);
        }
    }

    // find a set bit and clear it
    for (int i = 0; i < sizeof(info->failFlags) * 8; i++)
    {
        if (info->failFlags & (1 << i))
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

void bootInfo_setFailCountMax(struct BootInfo *info, uint32_t count)
{
    if (count >= sizeof(info->failFlags) * 8)
    {
        count = sizeof(info->failFlags) * 8 - 1;
    }

    info->failCountMax = count;
}

int bootInfo_setWdt(struct BootInfo *info, uint32_t timeout, uint32_t channelCount, uint32_t options)
{
    info->wdtChannelCount = channelCount;
    info->wdtOptions = options;
    info->wdtTimeout = timeout;

    if (channelCount != info->wdtChannelCount || options != info->wdtOptions || timeout != info->wdtTimeout)
    {
        return 1;
    }

    return BOOT_ERROR_SUCCESS;
}

bool appImage_isCurrent(const struct AppImageHeader *header, const struct BootInfo *bootInfo)
{
    struct AppImageHeader appHeader;

    int res = appImage_readHeader(&appHeader, &bootInfo->appStore);

    if (res < 0)
    {
        return false;
    }

    return 0 == memcmp(&appHeader.signatureInfo, &header->signatureInfo, sizeof(appHeader.signatureInfo));
}