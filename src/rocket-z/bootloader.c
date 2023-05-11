#include "bootloader.h"
#include <string.h>
#include <zephyr/sys/base64.h>

static struct FlashDevice *internalFlash;

static struct BootInfo *bootInfo;

void bootloader_run(struct FlashDevice *_internalFlash, struct FlashDevice *_imageFlash)
{
    internalFlash = _internalFlash;

    bootLogInit(_internalFlash, BOOT_LOG_ADDR);

    bootLog("INFO: Bootloader started");

    bootInfo = bootInfo_load(BOOT_INFO_ADDR);

    if (bootInfo->version != BOOT_VERSION_0_0)
    {
        bootLog("ERROR: Boot info version mismatch");
    }

#if 1 // For testing
    appImage_setStore(&bootInfo->img[0], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x20000, 0x20000);
    appImage_setName(&bootInfo->img[0].imageInfo, "image0");
    appImage_setEncryption(&bootInfo->img[0].imageInfo, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElHbYKCCRqq7Tl7kJrWf+8feaydJoH/SInipkPHoMiljLbo4X8u8oEaDZqmWpXAqN6bhvJYSUL/RpLLKS2kDD5A==", ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, 12032);
    appImage_setSignature(&bootInfo->img[0].imageInfo, "{\"version\":0,\"provider\":\"zodiac\",\"userId\":\"584\",\"time\":1680531112,\"variantPattern\":\"my-product-*:master\",\"size\":12025,\"sha256\":\"BYZX3lDea4TvtBbf8cQQQvrUIEyHoeWA9K9kNuq0o5U=\"}", "MEYCIQD4FqLfB7OzWUlGCEVbSOSoTohLd2fwp8a5VIP01D0NxwIhAPvgxdI2uUPcH/HhndPGbrxpkCRgSE+8K9GdKLoTIrFq");
    appImage_setLoadRequest(&bootInfo->img[0].imageInfo);
    appImage_setValid(&bootInfo->img[0], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");
#endif

    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (appImage_hasLoadRequest(&bootInfo->img[i].imageInfo))
        {
            bootLog("INFO: Image %d:%s has load request", i, bootInfo->img[i].imageInfo.imageName);

            // clear load request
            appImage_clearLoadRequest(&bootInfo->img[i].imageInfo);

            // save boot info
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);

            // verify new image
            int verified = appImage_verify(&bootInfo->img[i], bootInfo);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%s failed verification. Will not be loaded", i, bootInfo->img[i].imageInfo.imageName);
                appImage_setValid(&bootInfo->img[i], false);
                continue;
            }

            // verify checksum of new image
            verified = appImage_verifyChecksum(&bootInfo->img[i]);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%s failed checksum verification. Will not be loaded", i, bootInfo->img[i].imageInfo.imageName);
                appImage_setValid(&bootInfo->img[i], false);
                continue;
            }

            int res = loadImage(&bootInfo->img[i], bootInfo);

            if (res < 0)
            {
                bootLog("ERROR: Failed to load image %d:%s", i, bootInfo->img[i].imageInfo.imageName);
                continue;
            }

            appImage_setValid(&bootInfo->img[i], true);
            bootInfo_failClear(bootInfo);

            break;
        }
    }

    bootInfo_save(BOOT_INFO_ADDR, bootInfo);

    // lock memory
    int res;
    res = internalFlash->lock(0x0, BOOT_KEY_ADDR, FLASH_LOCK_WRITE);

    if (res < 0)
    {
        bootLog("ERROR: Failed to lock boot area. Restarting.");
        sys_reboot();
        return;
    }

    res = internalFlash->lock(BOOT_APP_ADDR, MIN(BOOT_MAX_APPIMAGE_SIZE, bootInfo->appStore.imageInfo.encryption.encryptedSize), FLASH_LOCK_WRITE);

    if (res < 0)
    {
        bootLog("WARNING: Failed to lock app area. Restarting.");
        sys_reboot();
        return;
    }

    res = internalFlash->lock(BOOT_KEY_ADDR, 512, FLASH_LOCK_ALL);

    if (res < 0)
    {
        bootLog("WARNING: Failed to lock secret area. Restarting.");
        sys_reboot();
        return;
    }

#if 0 // For testing
    // try read from locked memory
    uint8_t buf[0x10];

    int rres = internalFlash->read(BOOT_KEY_ADDR, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->read(0x00, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->read(BOOT_APP_ADDR + 512, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    buf[0] = 1;
    buf[1] = 2;
    buf[2] = 3;

    rres = internalFlash->write(BOOT_KEY_ADDR, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->write(0x00, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->write(BOOT_APP_ADDR + 512, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

#endif

    if (bootInfo->failCountMax > 0)
    {
        bootInfo_failFlag(bootInfo);
        if (bootInfo_getFailCount(bootInfo) > bootInfo->failCountMax)
        {
            bootLog("ERROR: Current image failed to clear fail flags many times (max %d). Rolling back", bootInfo->failCountMax);
            appImage_setValid(&bootInfo->appStore, false);
            rollback(bootInfo);
            return;
        }
    }

    // verify loaded image
    res = appImage_verify(&bootInfo->appStore, bootInfo);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify signature of loaded image");
        rollback(bootInfo);
    }

    res = appImage_verifyChecksum(&bootInfo->appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        rollback(bootInfo);
    }

#if 0 // For testing
    res = appImage_verifyChecksum(&bootInfo->img[0]);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        // return;
    }
#endif

    appImage_setValid(&bootInfo->appStore, true);

    bootInfo_save(BOOT_INFO_ADDR, bootInfo);

    bootInfo_free(bootInfo);

    // jump to loaded image
    // copid from ncs\v2.3.0\bootloader\mcuboot\boot\zephyr\main.c
    // irq_lock();
    //((void (*)(void))BOOT_APP_ADDR)();
}

void rollback(struct BootInfo *bootInfo)
{
    if (bootInfo->appStore.isValid)
    {
        // set invalid
        bootLog("INFO: Restarting to try again");
        appImage_setValid(&bootInfo->appStore, false);
        bootInfo_save(BOOT_INFO_ADDR, bootInfo);
        sys_reboot();
        return;
    }
    else
    {
        if (bootInfo->rollbackImageIndex >= 0 && bootInfo->rollbackImageIndex < ARRAY_SIZE(bootInfo->img))
        {
            bootLog("INFO: Rolling back to image %d:%s after restart", bootInfo->rollbackImageIndex, bootInfo->img[bootInfo->rollbackImageIndex].imageInfo.imageName);
            bootInfo->rollbackImageIndex = -1;
            appImage_setLoadRequest(&bootInfo->img[bootInfo->rollbackImageIndex]);
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);
            sys_reboot();
            return;
        }
        else
        {
            bootLog("INFO: No image is set as backup");

            for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
            {
                if (bootInfo->img[i].isValid && !appImage_isCurrent(&bootInfo->img[i].imageInfo, bootInfo))
                {
                    bootLog("INFO: Rolling back to image %d:%s after restart", i, bootInfo->img[i].imageInfo.imageName);
                    bootInfo->rollbackImageIndex = -1;
                    appImage_setLoadRequest(i);
                    bootInfo_save(BOOT_INFO_ADDR, bootInfo);
                    sys_reboot();
                    return;
                }
            }

            for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
            {
                if (bootInfo->img[i].isValid)
                {
                    bootLog("INFO: Rolling back to image %d:%s after restart", i, bootInfo->img[i].imageInfo.imageName);
                    bootInfo->rollbackImageIndex = -1;
                    appImage_setLoadRequest(i);
                    bootInfo_save(BOOT_INFO_ADDR, bootInfo);
                    sys_reboot();
                    return;
                }
            }

            bootLog("ERROR: No valid image can be rolled back to. Restarting.");

            sys_reboot();
            return;
        }
    }
}

int loadImage(struct AppImageStore *store, struct BootInfo *bootInfo)
{
    bootLog("INFO: Loading image %s", store->imageInfo.imageName);

    if (store->imageInfo.encryption.method != ENCRYPTION_EC_P256_AES_128_CBC_SHA_256)
        return; // no other encryption methods supported yet

    if (bootInfo->appStore.isValid)
    {
        // Find current image and set rollback image
        for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
        {
            if (bootInfo->img[i].isValid && appImage_isCurrent(&bootInfo->img[i].imageInfo, bootInfo))
            {
                bootLog("INFO: Image %d:%s is selected as backup", i, bootInfo->img[i].imageInfo.imageName);
                bootInfo->rollbackImageIndex = i;
                break;
            }
        }
    }
    else
    {
        bootInfo->rollbackImageIndex = -1;
    }

    bootLog("INFO: Starting image transfer");

    // load image

    int res = appImage_transfer(store, &bootInfo->appStore, bootInfo);

#if 0 // For testing
    struct AppImageStore st2;

    st2.maxSize = 0x20000;
    st2.startAddr = 0x40000;
    st2.storage = BOOT_IMG_STORAGE_INTERNAL_FLASH;

    res = appImage_transfer(&bootInfo->appStore, &st2, NULL);

    st2.startAddr = 0x60000;

    res = appImage_transfer(store, &st2, NULL);
#endif

    if (res < 0)
    {
        bootLog("ERROR: Failed to load image");
        return res;
    }

    bootLog("INFO: Image transfer complete");

    return 0;
}