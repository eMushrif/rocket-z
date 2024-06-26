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
     * @brief Must be implemented externally. Feed all active WDT channels.
     */
    void bootloader_wdtFeed();
	
	/**
     * @brief Must be implemented externally. Whether signature should be verified before running the app. Can be set to "false" if in debugging mode.
     */
    bool bootloader_isAppSecure();

    /**
     * @brief Must be implemented externally. Jump to app.
     * @param offset Offset to jump to
     */
    void bootloader_jump(size_t offset);

#ifdef __cplusplus
}
#endif

#endif // BOOTLOADER_H