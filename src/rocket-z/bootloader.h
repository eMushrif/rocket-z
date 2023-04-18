/**
 * @file bootloader.h
 * @brief Bootloader header file
 */

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include "controller.h"

void bootloader_run(struct FlashDevice *internalFlash, struct FlashDevice *imageFlash);

#endif // BOOTLOADER_H