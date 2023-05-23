#include "bootloader.h"
#include "config.h"
#include <string.h>
#include <zephyr/sys/base64.h>
#include <zephyr/kernel.h>

static struct BootFlashDevice *internalFlash;
struct BootInfoBuffer bootInfoBuffer;

void bootloader_run()
{
    internalFlash = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH);

    // lock bootloadaer memory
    int res = internalFlash->lock(0x0, ROCKETZ_BOOTLOADER_SIZE_MAX, FLASH_LOCK_WRITE);

    if (res < 0)
    {
        bootLog("ERROR: Failed to lock boot area.");
        bootloader_restart();
    }

    bootLogInit(internalFlash, ROCKETZ_LOG_ADDR);

    bootLog("INFO: Bootloader started");

    bootInfo_load(ROCKETZ_INFO_ADDR, &bootInfoBuffer);

    struct BootInfo *bootInfo = &bootInfoBuffer.bootInfo;

    if (bootInfo->version != BOOT_VERSION_0_0)
    {
        bootLog("ERROR: Boot info version not supported.");
        bootloader_restart();
    }

#if 1 // For testing
    appImage_setStore(&bootInfo->stores[0], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x20000, 0x20000);

    appImage_setStore(&bootInfo->stores[2], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x40000, 0x20000);

    struct AppImageHeader h;
    appImage_setName(&h, "image11111");
    appImage_setEncryption(&h, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQUpL0p7jyVL36SH/ZRdoWYbw6FCSlKAIQ+0uyQiFTbi3arpBe5yrv1RLzc+t1ioSGnfYrSN4STkzFcgCQjv37Q==", ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, 37456, 0x2cc8a1b9);
    appImage_setSignature(&h, "{\"authenticator\":\"Zodiac\",\"authorId\":\"9090\",\"time\":1680531112,\"variantPattern\":\"my-pro\",\"size\":37448,\"sha256\":\"rCQIM0QV7aedK1JUp6T4u4Der6hHUkgwwi/artFoemI=\"}", "MEUCIQDnVlvU8km2YR014pZL+ABq36jaiuqkRqSxEbAdH0F2eQIgEz9fFW7IPMQr5titiU7yFwIwPoM9zbwAo+90JvLqS4Q=", SIGNATURE_VERSION_0_0);
    appImage_setHeader(&h, IMAGE_HEADER_VERSION_0_0, 800);

    // appImage_setLoadRequest(&bootInfo->stores[2]);

    appImage_setHasImage(&bootInfo->stores[0], true);
    appImage_setHasImage(&bootInfo->stores[2], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");

    bootInfo->failCountMax = 3;
#endif

    struct AppImageHeader header;

    for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
    {
        if (appImage_hasLoadRequest(&bootInfo->stores[i]))
        {
            bootLog("INFO: Store #%d has load request", i);

            // clear load request
            appImage_clearLoadRequest(&bootInfo->stores[i]);

            // save boot info
            bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);

            // read image header

            int res = appImage_readHeader(&header, &bootInfo->stores[i]);

            if (res < 0)
            {
                bootLog("ERROR: Store %d has load request but failed to read image header of image. Will not be loaded.", i);
                appImage_setHasImage(&bootInfo->stores[i], false);
                continue;
            }

            bootLog("INFO: Found Image \"%.64s\" in store", header.imageName);

            // verify new image
            int verified = appImage_verify(&bootInfo->stores[i], bootInfo);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%.64s failed verification. Will not be loaded.", i, header.imageName);
                appImage_setHasImage(&bootInfo->stores[i], false);
                continue;
            }

#if 1
            // verify checksum of new image
            verified = appImage_verifyChecksum(&bootInfo->stores[i]);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%.64s failed checksum verification. Will not be loaded.", i, header.imageName);
                appImage_setHasImage(&bootInfo->stores[i], false);
                continue;
            }
#endif
            bootLog("INFO: Loading image %.64s", header.imageName);

            res = loadImage(&bootInfo->stores[i], bootInfo);

            if (res < 0)
            {
                bootLog("ERROR: Failed to load image %d:%.64s", i, header.imageName);
                continue;
            }

            appImage_setHasImage(&bootInfo->stores[i], true);

            bootInfo_failClear(bootInfo);

            break;
        }
    }

    bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);

    res = appImage_readHeader(&header, &bootInfo->appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to read image header of loaded image.");
        appImage_setHasImage(&bootInfo->appStore, false);
        rollback();
    }

    res = internalFlash->lock(ROCKETZ_APP_ADDR, MIN(ROCKETZ_MAX_APPIMAGE_SIZE, header.encryption.encryptedSize), FLASH_LOCK_WRITE);

    if (res < 0)
    {
        bootLog("WARNING: Failed to lock app area.");
        bootloader_restart();
    }

    res = internalFlash->lock(ROCKETZ_KEY_ADDR, 512, FLASH_LOCK_ALL);

    if (res < 0)
    {
        bootLog("WARNING: Failed to lock secret area.");
        bootloader_restart();
    }

#if 0 // For testing
    // try read from locked memory
    uint8_t buf[0x10];

    int rres = internalFlash->read(ROCKETZ_KEY_ADDR, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->read(0x00, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->read(ROCKETZ_APP_ADDR + 512, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    buf[0] = 1;
    buf[1] = 2;
    buf[2] = 3;

    rres = internalFlash->write(ROCKETZ_KEY_ADDR, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->write(0x00, buf, 0x10);

    if (rres < 0)
    {
        bootLog("ERROR: Failed to read from locked memory");
    }

    rres = internalFlash->write(ROCKETZ_APP_ADDR + 512, buf, 0x10);

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
            bootLog("ERROR: Current image failed to clear fail flags many times (max %d). Rolling back.", bootInfo->failCountMax);
            appImage_setHasImage(&bootInfo->appStore, false);
            rollback();
        }
    }

    // verify loaded image
    res = appImage_verifySignature(&header);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify signature of loaded image");
        rollback();
    }

    res = appImage_verifyChecksum(&bootInfo->appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        rollback();
    }

#if 0 // For testing
    res = appImage_verifyChecksum(&bootInfo->stores[0]);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        // return;
    }
#endif

    appImage_setHasImage(&bootInfo->appStore, true);

    bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);

    // jump to loaded image
    // copid from ncs\v2.3.0\bootloader\mcuboot\boot\zephyr\main.c

    bootloader_jump();
}

// select a rollback image
// if appStore hasImage is true, it will be set to false first without rolling back
// if appStore hasImage is false, it will try to find a rollback image and make a load request
// should restart the system after calling this function
void rollback()
{
    struct BootInfo *bootInfo = &bootInfoBuffer.bootInfo;

    if (appImage_hasImage(&bootInfo->appStore))
    {
        // set invalid image
        bootLog("INFO: Same image will be tried again");
        appImage_setHasImage(&bootInfo->appStore, false);
        bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);
        bootloader_restart();
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
            bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);
            bootloader_restart();
        }
        else
        {
            bootLog("INFO: No image is set as backup");

            // try to find any store with an image image that is not same as the current image
            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                if (!appImage_hasImage(&bootInfo->stores[i]))
                    continue;

                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                    continue;

                if (!appImage_isCurrent(&header, bootInfo))
                {
                    bootLog("INFO: Found a different image to rollback to");
                    bootLog("INFO: Rolling back to image %d:%.64s after restart", i, header.imageName);
                    bootInfo->rollbackImageIndex = -1;
                    appImage_setLoadRequest(&bootInfo->stores[i]);
                    bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);
                    bootloader_restart();
                }
            }

            // try to find any image at all
            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                if (!appImage_hasImage(&bootInfo->stores[i]))
                    continue;

                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                    continue;

                bootLog("INFO: Couldn't find a different image to rollback to. Will try to rollback to the same image.");
                bootLog("INFO: Rolling back to image %d:%.64s after restart", i, header.imageName);
                bootInfo->rollbackImageIndex = -1;
                appImage_setLoadRequest(&bootInfo->stores[i]);
                bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);
                bootloader_restart();
            }

            // find any store and verify the image regalrdless of the value of hasImage
            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                    continue;

                appImage_setHasImage(&bootInfo->stores[i], true);

                if (0 != appImage_verify(&bootInfo->stores[i], bootInfo))
                {
                    appImage_setHasImage(&bootInfo->stores[i], false);
                    continue;
                }

                bootLog("INFO: No store has an image to rollback to. Will try any store even if marked as not hasImage.");
                bootLog("INFO: Rolling back to image %d:%.64s after restart", i, header.imageName);
                bootInfo->rollbackImageIndex = -1;
                appImage_setLoadRequest(&bootInfo->stores[i]);
                bootInfo_save(ROCKETZ_INFO_ADDR, &bootInfoBuffer);
                bootloader_restart();
            }

            bootLog("ERROR: No valid image can be rolled back to.");

            bootloader_restart();
        }
    }
}

int loadImage(struct AppImageStore *store, struct BootInfo *bootInfo)
{
    if (appImage_hasImage(&bootInfo->appStore))
    {
        // read store header
        struct AppImageHeader header;
        int res = appImage_readHeader(&header, store);

        if (res >= 0 && !appImage_isCurrent(&header, bootInfo)) // if we're not updating with the same loaded image
        {
            // Find current image and set rollback image
            for (int i = 0; i < ARRAY_SIZE(bootInfo->stores); i++)
            {
                // read header
                int res = appImage_readHeader(&header, &bootInfo->stores[i]);
                if (res < 0)
                {
                    continue;
                }

                if (appImage_hasImage(&bootInfo->stores[i]) && appImage_isCurrent(&header, bootInfo))
                {
                    bootLog("INFO: Image %d:%.64s is selected as backup", i, header.imageName);
                    bootInfo->rollbackImageIndex = i;
                    break;
                }
            }
        }
    }

    bootLog("INFO: Starting image transfer");

    // load image

    int res = appImage_transfer(store, &bootInfo->appStore, &bootInfoBuffer);

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