/**
 * @file config.h
 * @brief Board-specific configurations for RocketZ
 */

#ifndef CONFIG_H
#define CONFIG_H

#ifdef CONFIG_BOARD_NRF52833DK_NRF52833
#ifndef ROCKETZ_FLASH_BLOCK_SIZE
#define ROCKETZ_FLASH_BLOCK_SIZE 0x1000
#endif

#ifndef ROCKETZ_FLASH_WRITE_ALIGNMENT
#define ROCKETZ_FLASH_WRITE_ALIGNMENT 4
#endif

#ifndef ROCKETZ_APP_ADDR
#define ROCKETZ_APP_ADDR 0x13000
#endif

#ifndef ROCKETZ_DEFAULT_HEADER_SIZE
#define ROCKETZ_DEFAULT_HEADER_SIZE 0x400
#endif

#ifndef ROCKETZ_INTERNAL_FLASH_SIZE
#define ROCKETZ_INTERNAL_FLASH_SIZE 0x80000 // 512KB
#endif

#ifndef ROCKETZ_MAX_APPIMAGE_SIZE
#define ROCKETZ_MAX_APPIMAGE_SIZE (ROCKETZ_INTERNAL_FLASH_SIZE - ROCKETZ_APP_ADDR) // 1MB - Bootloder size
#endif

#ifndef ROCKETZ_INFO_ADDR
#define ROCKETZ_INFO_ADDR (ROCKETZ_APP_ADDR - ROCKETZ_FLASH_BLOCK_SIZE)
#endif

#ifndef ROCKETZ_LOG_ADDR
#define ROCKETZ_LOG_ADDR (ROCKETZ_APP_ADDR - (2 * ROCKETZ_FLASH_BLOCK_SIZE))
#endif

#ifndef ROCKETZ_KEY_ADDR
#define ROCKETZ_KEY_ADDR (ROCKETZ_APP_ADDR - (3 * ROCKETZ_FLASH_BLOCK_SIZE))
#endif

#ifndef ROCKETZ_BOOTLOADER_SIZE_MAX
#define ROCKETZ_BOOTLOADER_SIZE_MAX ROCKETZ_KEY_ADDR
#endif

#ifndef ROCKETZ_NO_LOCK_HASH
#define ROCKETZ_NO_LOCK_HASH                                                                                                                                                                           \
    {                                                                                                                                                                                                  \
        0x6f, 0xa6, 0xfd, 0xd3, 0x6b, 0x6f, 0xc9, 0x2a, 0x61, 0x60, 0xdf, 0xb1, 0x65, 0x49, 0x47, 0xc6, 0x3f, 0x7e, 0x52, 0x23, 0x49, 0xe7, 0x3e, 0x99, 0xb8, 0x2d, 0x3d, 0xee, 0x06, 0x03, 0x9d, 0xf5 \
    }
#endif

#ifndef ROCKETZ_WDT_TIMEOUT_DEFAULT
#define ROCKETZ_WDT_TIMEOUT_DEFAULT 300000
#endif

#ifndef ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
#define ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE 512
#endif
#else
#error "Board not supported"
#endif

#endif // CONFIG_H