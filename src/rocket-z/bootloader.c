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

    // For testing
    appImage_setStore(&bootInfo->img[0], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x20000, 0x20000);
    appImage_setName(&bootInfo->img[0].imageInfo, "image0");
    appImage_setEncryption(&bootInfo->img[0].imageInfo, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElHbYKCCRqq7Tl7kJrWf+8feaydJoH/SInipkPHoMiljLbo4X8u8oEaDZqmWpXAqN6bhvJYSUL/RpLLKS2kDD5A==", ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, 12032);
    appImage_setSignature(&bootInfo->img[0].imageInfo, "{\"version\":0,\"provider\":\"zodiac\",\"userId\":\"584\",\"time\":1680531112,\"variantPattern\":\"my-product-*:master\",\"size\":12025,\"sha256\":\"BYZX3lDea4TvtBbf8cQQQvrUIEyHoeWA9K9kNuq0o5U=\"}", "MEYCIQD4FqLfB7OzWUlGCEVbSOSoTohLd2fwp8a5VIP01D0NxwIhAPvgxdI2uUPcH/HhndPGbrxpkCRgSE+8K9GdKLoTIrFq");
    appImage_setLoadRequest(&bootInfo->img[0].imageInfo);
    appImage_setValid(&bootInfo->img[0], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");

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
                continue;
            }

            int res = loadImage(&bootInfo->img[i], bootInfo);

            if (res < 0)
            {
                bootLog("ERROR: Failed to load image %d:%s", i, bootInfo->img[i].imageInfo.imageName);
                continue;
            }

            break;
        }
    }

    // lock memory

    // verify loaded image
    int res = appImage_verify(&bootInfo->appStore, bootInfo);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify signature of loaded image");
        // return;
    }

    res = appImage_verifyChecksum(&bootInfo->appStore);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        // return;
    }

#if 0 // For testing
    res = appImage_verifyChecksum(&bootInfo->img[0]);

    if (res < 0)
    {
        bootLog("ERROR: Failed to verify checksum of loaded image");
        // return;
    }
#endif

    bootInfo_free(bootInfo);

    // run loaded image
}

int loadImage(struct AppImageStore *store, struct BootInfo *bootInfo)
{
    bootLog("INFO: Loading image %s", store->imageInfo.imageName);

    if (store->imageInfo.encryption.method != ENCRYPTION_EC_P256_AES_128_CBC_SHA_256)
        return; // no other encryption methods supported yet

    // Find current image and set rollback image
    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (bootInfo->img[i].isValid && appImage_isCurrent(&bootInfo->img[i].imageInfo, bootInfo))
        {
            bootLog("INFO: Image %d:%s is selected for rollback", i, bootInfo->img[i].imageInfo.imageName);
            bootInfo->rollbackImageIndex = i;
            break;
        }
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