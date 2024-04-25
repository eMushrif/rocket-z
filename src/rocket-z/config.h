/**
 * @file config.h
 * @brief Board-specific configurations for RocketZ
 */

#ifndef CONFIG_H
#define CONFIG_H

#if __has_include("autoconf.h")
#include "autoconf.h"
#endif

#ifdef CONFIG_BOARD_NRF52833DK_NRF52833

#elif defined(CONFIG_IMG_GEN)
#else
#error "Board not supported"
#endif

#ifndef CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
#define CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE 512
#endif

#endif // CONFIG_H