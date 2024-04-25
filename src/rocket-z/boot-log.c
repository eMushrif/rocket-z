#include "boot-log.h"
#include "config.h"
#include <string.h>
#include <stdarg.h>

static int logStartIndex = 0;
static int logIndex;
static const struct BootFlashDevice *logFlash;

#ifdef CONFIG_ROCKETZ_BOOTLOG
enum BootError bootLogInit(const struct BootFlashDevice *flash, uint32_t address)
{
    logFlash = flash;
    logIndex = address;
    logStartIndex = address;

    char buffer[CONFIG_ROCKETZ_FLASH_BLOCK_SIZE];

    int res = logFlash->read(logIndex, buffer, CONFIG_ROCKETZ_FLASH_BLOCK_SIZE);

    if (res < 0)
    {
        logStartIndex = 0;
        return res;
    }

    for (int i = 0; i < CONFIG_ROCKETZ_FLASH_BLOCK_SIZE; i++)
    {
        if (buffer[i] == 0xFF)
        {
            logIndex += i;
            break;
        }
    }

    return BOOT_ERROR_SUCCESS;
}
#endif

#ifdef CONFIG_ROCKETZ_BOOTLOG
void bootLog(const char *format, ...)
{
    if (logStartIndex == 0)
        return; // not initialized

    if (logIndex - logStartIndex >= (3 * CONFIG_ROCKETZ_FLASH_BLOCK_SIZE) / 4)
    {
        logFlash->erase(logStartIndex, CONFIG_ROCKETZ_FLASH_BLOCK_SIZE);
        logIndex = logStartIndex;
    }

    if (logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT != 0)
    {
        // make sure our writing is alligned to 4 bytes
        uint8_t j[CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT];

        logFlash->read(logIndex - logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT, j, CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT);
        memset(j + logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT, 0, CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT - logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT);

        int wres = logFlash->write(logIndex - logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT, j, CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT);

        logIndex = logIndex - logIndex % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT + (wres >= 0 ? wres : 0);
    }

    va_list args;
    va_start(args, format);

    char buffer[256];
    memset(buffer, 0x00, sizeof(buffer));

    vsprintf(buffer, format, args);

    va_end(args);

    buffer[sizeof(buffer) - 1] = 0x00; // make sure we have null terminator

    int wres = logFlash->write(logIndex, buffer, strlen(buffer) + 1);

    logIndex += wres >= 0 ? wres : 0;
}
#else
attribute((weak)) void bootLog(const char *format, ...)
{
}
#endif