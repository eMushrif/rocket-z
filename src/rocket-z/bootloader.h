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

    /**
     * @brief Run the bootloader logic
     */
    void bootloader_run();

    /**
     * @brief Must be implemented externally. Restart the system.
     */
    void bootloader_restart();

    /**
     * @brief Must be implemented externally. Jump to app.
     */
    void bootloader_jump();

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_H