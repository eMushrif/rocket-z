/**
 * @file bootloader.h
 * @brief Bootloader header file
 */

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include "controller.h"

#ifndef BOOT_INFO_ADDR
#define BOOT_INFO_ADDR (0xC000 - FLASH_BLOCK_SIZE) // 0xB000. 0xC000 is the typical start of app. 0x1000 is the typical flash block size
#endif

#ifndef BOOT_LOG_ADDR
#define BOOT_LOG_ADDR (0xC000 - (2 * FLASH_BLOCK_SIZE)) // 0xA000. 0xC000 is the typical start of app.
#endif

void bootloader_run(struct FlashDevice *internalFlash, struct FlashDevice *imageFlash);

#endif // BOOTLOADER_H