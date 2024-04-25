/**
 * @file boot-log.h
 * @brief Functions to log boot information
 * @details This is normally used by the bootloader to log boot information to flash.
 */

#ifndef BOOT_LOG_H
#define BOOT_LOG_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include "structs.h"

    /**
     * \brief Log event
     * \param fmt Format string. similar to printf
     * \param ... Format arguments
     */
    void bootLog(const char *fmt, ...);

    /**
     * \brief Initialize the boot log
     * \param flash Flash device used to store the log
     * \param address Address in flash where the log is stored
     * \return 0 on success, BootError on error
     */
    enum BootError bootLogInit(const struct BootFlashDevice *flash, uint32_t address);

#ifdef __cplusplus
}
#endif

#endif // BOOT_LOG_H