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

#ifndef ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
#define ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE 512
#endif
#else
#error "Board not supported"
#endif

#endif // CONFIG_H