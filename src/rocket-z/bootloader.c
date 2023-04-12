#include "bootloader.h"

static struct FlashDevice *internalFlash;
static struct FlashDevice *imageFlash;

void bootloader_run(struct FlashDevice *_internalFlash, struct FlashDevice *_imageFlash)
{
    internalFlash = _internalFlash;
    imageFlash = _imageFlash;

    bootLogInit(_internalFlash, BOOT_LOG_ADDR);

    bootLog("INFO: Bootloader started");
}