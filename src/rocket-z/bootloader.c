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

    for (int i = 0; i < 4; i++)
    {
        image_setLoadRequest(&bootInfo->img[0].imageInfo);
        bootInfo_save(BOOT_INFO_ADDR, bootInfo);
        image_clearLoadRequest(&bootInfo->img[0].imageInfo);
        bootInfo_save(BOOT_INFO_ADDR, bootInfo);
    }

    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (image_hasLoadRequest(&bootInfo->img[i].imageInfo))
        {
            bootLog("INFO: Image %d:%s has load request", i, bootInfo->img[i].imageInfo.imageName);
        }
    }

    bootInfo_free(bootInfo);
}