#include "bootloader.h"

static struct FlashDevice *internalFlash;
static struct FlashDevice *imageFlash;

static struct BootInfo *bootInfo;

void bootloader_run(struct FlashDevice *_internalFlash, struct FlashDevice *_imageFlash)
{
    internalFlash = _internalFlash;
    imageFlash = _imageFlash;

    bootLogInit(_internalFlash, BOOT_LOG_ADDR);

    bootLog("INFO: Bootloader started");

    bootInfo = bootInfo_load(BOOT_INFO_ADDR);

    if (bootInfo->version != BOOT_VERSION_0_0)
    {
        bootLog("ERROR: Boot info version mismatch");
    }

    // For testing
    image_setName(&bootInfo->img[0].imageInfo, "image0");
    image_setSignature(&bootInfo->img[0].imageInfo, "{\"version\":0,\"provider\":\"zodiac\",\"userId\":\"584\",\"time\":1680531112,\"variantPattern\":\"my-product-*:master\",\"size\":256121,\"sha256\":\"IiSuHNuVCD86YRg5lPAMFrRm8hjIp4jB3jncUhjQHRs=\"}", "1hLCzGyyV48LJ9CY0bsGCX0B5FKI2ELtA6obuBC0AiBeH04vgVWLaHNGtSwKFM/SZVleRzi/jxIzYpJ1tZ0pZA==");
    image_setLoadRequest(&bootInfo->img[0].imageInfo);
    image_setValid(&bootInfo->img[0], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");

    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (image_hasLoadRequest(&bootInfo->img[i].imageInfo))
        {
            bootLog("INFO: Image %d:%s has load request", i, bootInfo->img[i].imageInfo.imageName);

            // clear load request
            image_clearLoadRequest(&bootInfo->img[i].imageInfo);

            // save boot info
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);

            struct SignatureMessage signatureMessage;

            // verify new image
            image_verifySignature(&bootInfo->img[i], bootInfo, &signatureMessage);

            // Find current image and set rollback image
            for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
            {
                if (bootInfo->img[i].isValid && image_isCurrent(&bootInfo->img[i].imageInfo, bootInfo))
                {
                    bootLog("INFO: Image %d:%s is selected for rollback", i, bootInfo->img[i].imageInfo.imageName);
                    bootInfo->rollbackImageIndex = i;
                    break;
                }
            }

            // save boot info
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);
        }
    }
    bootInfo_free(bootInfo);
}