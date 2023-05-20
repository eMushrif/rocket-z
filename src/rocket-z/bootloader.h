/**
 * @file bootloader.h
 * @brief Bootloader header file
 */

#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "controller.h"

    void bootloader_run();

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_H