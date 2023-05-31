#include "config.h"
#include "controller.h"

struct BootInfo *bootInfo_load(uint32_t address, struct BootInfoBuffer *buff)
{
    struct BootInfo *info = &buff->bootInfo;

    if (NULL == info)
        return NULL;

    int res = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, info, sizeof(struct BootInfo));

    if (res < 0)
    {
        bootLog("ERROR: Failed to read boot info from flash");
        return NULL;
    }

    // copy the original boot info to the second half of the buffer
    memcpy(&buff->bootInfo_orig, &buff->bootInfo, sizeof(struct BootInfo));

    if (info->version != BOOT_VERSION_0_0)
    {
        // Boot information not loaded, or different version. Reset info.
        memset(info, 0, sizeof(struct BootInfo));

        // set bootloader name
        strcpy(info->bootloaderName, "rocket-zn");

        // set boot version
        info->version = BOOT_VERSION_0_0;

        info->rollbackImageIndex = -1;

        info->wdtTimeout = ROCKETZ_WDT_TIMEOUT_DEFAULT;
    }

    // make sure appStore parameters are not changed
    bootInfo_setStore(&info->appStore, BOOT_IMG_STORAGE_INTERNAL_FLASH, ROCKETZ_APP_ADDR, ROCKETZ_MAX_APPIMAGE_SIZE);

    res = bootInfo_save(address, buff);

    if (res < 0)
    {
        bootLog("ERROR: Failed to update boot into from flash");
        return NULL;
    }

    return info;
}

enum BootError bootInfo_save(uint32_t address, const struct BootInfoBuffer *info)
{
    const struct BootInfoBuffer *buffer = (const struct BootInfoBuffer *)info;

    // if info is the same as the one in flash, don't write it
    if (memcmp(&buffer->bootInfo, &buffer->bootInfo_orig, sizeof(struct BootInfo)) == 0)
        return BOOT_ERROR_SUCCESS;

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

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, (struct BootInfo *)(&buffer->bootInfo), sizeof(struct BootInfo));
    if (memcmp(&buffer->bootInfo_orig, &buffer->bootInfo, sizeof(struct BootInfo)) != 0)
    {
        // data wasn't written correctly. erase and write again
        bootLog("INFO: Erasing boot info for rewrite");
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->erase(address, sizeof(struct BootInfo));
        bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->write(address, info, sizeof(struct BootInfo));
    }

    bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH)->read(address, (struct BootInfo *)(&buffer->bootInfo), sizeof(struct BootInfo));
    if (memcmp(&buffer->bootInfo_orig, &buffer->bootInfo, sizeof(struct BootInfo)) != 0)
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