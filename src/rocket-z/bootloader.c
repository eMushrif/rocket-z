#include "bootloader.h"
#include <string.h>
#include <zephyr/sys/base64.h>

static struct FlashDevice *internalFlash;

void bootloader_run(struct FlashDevice *_internalFlash, struct FlashDevice *_imageFlash)
{
    internalFlash = _internalFlash;

    bootLogInit(_internalFlash, BOOT_LOG_ADDR);

    bootLog("INFO: Bootloader started");

    struct BootInfo bootInfo;
    bootInfo_load(BOOT_INFO_ADDR, &bootInfo);

    if (bootInfo.version != BOOT_VERSION_0_0)
    {
        bootLog("ERROR: Boot info version not supported. Restarting.");
        sys_reboot();
    }

#if 0 // For testing
    appImage_setStore(&bootInfo.stores[0], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x20000, 0x20000);
    appImage_setName(&bootInfo.stores[0].imageInfo, "image0");
    appImage_setEncryption(&bootInfo.stores[0].imageInfo, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElHbYKCCRqq7Tl7kJrWf+8feaydJoH/SInipkPHoMiljLbo4X8u8oEaDZqmWpXAqN6bhvJYSUL/RpLLKS2kDD5A==", ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, 12032);
    appImage_setSignature(&bootInfo.stores[0].imageInfo, "{\"version\":0,\"provider\":\"zodiac\",\"userId\":\"584\",\"time\":1680531112,\"variantPattern\":\"my-product-*:master\",\"size\":12025,\"sha256\":\"BYZX3lDea4TvtBbf8cQQQvrUIEyHoeWA9K9kNuq0o5U=\"}", "MEYCIQD4FqLfB7OzWUlGCEVbSOSoTohLd2fwp8a5VIP01D0NxwIhAPvgxdI2uUPcH/HhndPGbrxpkCRgSE+8K9GdKLoTIrFq");
    appImage_setLoadRequest(&bootInfo.stores[0].imageInfo);
    appImage_setValid(&bootInfo.stores[0], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");
#endif

    struct AppImageHeader header;

    for (int i = 0; i < ARRAY_SIZE(bootInfo.stores); i++)
    {
        if (appImage_hasLoadRequest(&bootInfo.stores[i]))
        {
            // read image header

            int res = appImage_readHeader(&header, &bootInfo.stores[i]);

            if (res < 0)
            {
                bootLog("ERROR: Store %d has load request but failed to read image header of image. Will not be loaded", i);
                appImage_setValid(&bootInfo.stores[i], false);
                continue;
            }

            bootLog("INFO: Image %d:%.64s has load request", i, header.imageName);

            // clear load request
            appImage_clearLoadRequest(&bootInfo.stores[i]);

            // save boot info
            bootInfo_save(BOOT_INFO_ADDR, &bootInfo);

            // verify new image
            int verified = appImage_verify(&bootInfo.stores[i], &bootInfo);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%.64s failed verification. Will not be loaded", i, header.imageName);
                appImage_setValid(&bootInfo.stores[i], false);
                continue;
            }

            // verify checksum of new image
            verified = appImage_verifyChecksum(&bootInfo.stores[i]);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%.64s failed checksum verification. Will not be loaded", i, header.imageName);
                appImage_setValid(&bootInfo.stores[i], false);
                continue;
            }

            bootLog("INFO: Loading image %.64s", header.imageName);

            res = loadImage(&bootInfo.stores[i], &bootInfo);

            if (res < 0)
            {
                bootLog("ERROR: Failed to load image %d:%.64s", i, header.imageName);
                continue;
            }

            appImage_setValid(&bootInfo.stores[i], true);
            bootInfo_failClear(&bootInfo);

            break;
        }
    }

    bootInfo_save(BOOT_INFO_ADDR, &bootInfo);

    int res = appImage_readHeader(&header, &bootInfo.appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header of loaded image. Restarting.");
        appImage_setValid(&bootInfo.appStore, false);
        rollback(&bootInfo);
        return;
    }

    // lock memory
    res = internalFlash->lock(0x0, BOOT_KEY_ADDR, FLASH_LOCK_WRITE);

    if (res < 0)
    {
        bootLog("ERROR: Failed to lock boot area. Restarting.");
        sys_reboot();
        return;
    }

    res = internalFlash->lock(BOOT_APP_ADDR, MIN(BOOT_MAX_APPIMAGE_SIZE, header.encryption.encryptedSize), FLASH_LOCK_WRITE);

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

    if (bootInfo.failCountMax > 0)
    {
        bootInfo_failFlag(&bootInfo);
        if (bootInfo_getFailCount(&bootInfo) > bootInfo.failCountMax)
        {
            bootLog("ERROR: Current image failed to clear fail flags many times (max %d). Rolling back", bootInfo.failCountMax);
            appImage_setValid(&bootInfo.appStore, false);
            rollback(&bootInfo);
            return;
        }
    }

    // verify loaded image
    res = appImage_verify(&bootInfo.appStore, &bootInfo);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify signature of loaded image");
        rollback(&bootInfo);
    }

    res = appImage_verifyChecksum(&bootInfo.appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        rollback(&bootInfo);
    }

#if 0 // For testing
    res = appImage_verifyChecksum(&bootInfo.stores[0]);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        // return;
    }
#endif

    appImage_setValid(&bootInfo.appStore, true);

    bootInfo_save(BOOT_INFO_ADDR, &bootInfo);

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
        // read header
        struct AppImageHeader header;

        if (bootInfo->rollbackImageIndex >= 0 && bootInfo->rollbackImageIndex < ARRAY_SIZE(bootInfo->stores))
        {
            int res = appImage_readHeader(&header, &bootInfo->stores[bootInfo->rollbackImageIndex]);
            if (res < 0)
                bootLog("WARNING: Failed to read image header of rollback image. Will try it anyway.");

            bootLog("INFO: Rolling back to image %d:%.64s after restart", bootInfo->rollbackImageIndex, header.imageName);
            bootInfo->rollbackImageIndex = -1;
            appImage_setLoadRequest(&bootInfo->stores[bootInfo->rollbackImageIndex]);
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);
            sys_reboot();
            return;
        }
        else
        {
            bootLog("INFO: No image is set as backup");

            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                    continue;

                if (bootInfo->stores[i].isValid && !appImage_isCurrent(&header, bootInfo))
                {

                    bootLog("INFO: Rolling back to image %d:%.64s after restart", i, header.imageName);
                    bootInfo->rollbackImageIndex = -1;
                    appImage_setLoadRequest(&bootInfo->stores[i]);
                    bootInfo_save(BOOT_INFO_ADDR, bootInfo);
                    sys_reboot();
                    return;
                }
            }

            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                    continue;

                if (bootInfo->stores[i].isValid)
                {
                    bootLog("INFO: Rolling back to image %d:%.64s after restart", i, header.imageName);
                    bootInfo->rollbackImageIndex = -1;
                    appImage_setLoadRequest(&bootInfo->stores[i]);
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
    if (bootInfo->appStore.isValid)
    {
        // Find current image and set rollback image
        for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
        {
            // read header
            struct AppImageHeader header;
            int res = appImage_readHeader(&header, &bootInfo->stores[i]);
            if (res < 0)
            {
                continue;
            }

            if (bootInfo->stores[i].isValid && appImage_isCurrent(&header, bootInfo))
            {
                bootLog("INFO: Image %d:%.64s is selected as backup", i, header.imageName);
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