/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/data/json.h>
#include "string.h"
#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/fatal.h>
#include <fprotect.h>
#include <hal/nrf_clock.h>
#include <zephyr/drivers/watchdog.h>
#include "rocket-z/config.h"
#include "arm_cleanup.h"
#include "rocket-z/config.h"
#include <zephyr/sys/reboot.h>

#include "nrfx_wdt.h"

#include "rocket-z/bootloader.h"

#define FLASH_DEVICE DT_LABEL(DT_INST(0, nordic_qspi_nor))

static const struct device *internalFlashDeviceId;
static const struct device *externalFlashDeviceId;

int zephyrFlashReadExt(size_t address, void *data, size_t size)
{
	if (!device_is_ready(externalFlashDeviceId))
	{
		return BOOT_ERROR_UNKNOWN_DEVICE;
	}

	else
	{
		if (address + size > CONFIG_ROCKETZ_EXTERNAL_FLASH_SIZE)
		{
			return BOOT_ERROR_INVALID_ADDRESS;
		}

		if (fprotect_is_protected(address) & 2)
		{
			return BOOT_ERROR_MEMORY_LOCKED;
		}

		int res = flash_read(externalFlashDeviceId, address, data, size);
		return res >= 0 ? size : res;
	}
}

int zephyrFlashEraseExt(size_t address, size_t size)
{
	if (!device_is_ready(externalFlashDeviceId))
	{
		return BOOT_ERROR_UNKNOWN_DEVICE;
	}

	else
	{
		if (address + size > CONFIG_ROCKETZ_EXTERNAL_FLASH_SIZE)
		{
			return BOOT_ERROR_INVALID_ADDRESS;
		}

		if (fprotect_is_protected(address) & 1)
		{
			return BOOT_ERROR_MEMORY_LOCKED;
		}

		// allign the erase region with the ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE
		size = size % CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE ? size + CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE - size % CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE : size;

		int res = 0;

		// do erase in chunks of 8 blocks to prevent WDT triggering
		for (int i = 0; i < size;)
		{
			bootloader_wdtFeed();

			size_t eraseSize = MIN(size - i, CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE * 8);

			res = flash_erase(externalFlashDeviceId, address + i, eraseSize);
			if (res < 0)
			{
				return res;
			}

			i += eraseSize;
		}

		return res;
	}
}

int zephyrFlashWriteExt(size_t address, const void *data, size_t size)
{
	if (!device_is_ready(externalFlashDeviceId))
	{
		return BOOT_ERROR_UNKNOWN_DEVICE;
	}

	else
	{
		if (address + size > CONFIG_ROCKETZ_EXTERNAL_FLASH_SIZE)
		{
			return BOOT_ERROR_INVALID_ADDRESS;
		}

		if (fprotect_is_protected(address) & 1)
		{
			return BOOT_ERROR_MEMORY_LOCKED;
		}

		// data must be aligned in 4 bytes
		int actSize = size % CONFIG_ROCKETZ_EXTERNAL_FLASH_WRITE_ALIGNMENT ? size + CONFIG_ROCKETZ_EXTERNAL_FLASH_WRITE_ALIGNMENT - size % CONFIG_ROCKETZ_EXTERNAL_FLASH_WRITE_ALIGNMENT : size;

		int res = flash_write(externalFlashDeviceId, address, data, actSize);
		return res >= 0 ? size : res;
	}
}

int zephyrFlashLockExt(size_t address, size_t size, enum BootFlashLockType lockType)
{
	if (!device_is_ready(externalFlashDeviceId))
	{
		return BOOT_ERROR_UNKNOWN_DEVICE;
	}

	else
	{
		if (address + size > CONFIG_ROCKETZ_EXTERNAL_FLASH_SIZE)
		{
			return BOOT_ERROR_MEMORY_LOCKED;
		}

		// round size up to flash block size
		size = size % CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE ? size + CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE - size % CONFIG_ROCKETZ_EXTERNAL_FLASH_BLOCK_SIZE : size;
		return lockType == FLASH_LOCK_WRITE ? fprotect_area(address, size) : fprotect_area_no_access(address, size);
	}
}

int zephyrFlashRead(size_t address, void *data, size_t size)
{
	if (address + size > CONFIG_ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_INVALID_ADDRESS;
	}

	if (fprotect_is_protected(address) & 2)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	int res = flash_read(internalFlashDeviceId, address, data, size);
	return res >= 0 ? size : res;
}

int zephyrFlashErase(size_t address, size_t size)
{
	if (address + size > CONFIG_ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_INVALID_ADDRESS;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// allign the erase region with the CONFIG_ROCKETZ_FLASH_BLOCK_SIZE
	size = size % CONFIG_ROCKETZ_FLASH_BLOCK_SIZE ? size + CONFIG_ROCKETZ_FLASH_BLOCK_SIZE - size % CONFIG_ROCKETZ_FLASH_BLOCK_SIZE : size;

	int res = 0;

	// do erase in chunks of 8 blocks to prevent WDT triggering
	for (int i = 0; i < size;)
	{
		bootloader_wdtFeed();

		size_t eraseSize = MIN(size - i, CONFIG_ROCKETZ_FLASH_BLOCK_SIZE * 8);

		res = flash_erase(internalFlashDeviceId, address + i, eraseSize);
		if (res < 0)
		{
			return res;
		}

		i += eraseSize;
	}

	return res;
}

int zephyrFlashWrite(size_t address, const void *data, size_t size)
{
	if (address + size > CONFIG_ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_INVALID_ADDRESS;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// data must be aligned in 4 bytes
	int actSize = size % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT ? size + CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT - size % CONFIG_ROCKETZ_FLASH_WRITE_ALIGNMENT : size;
	int res = flash_write(internalFlashDeviceId, address, data, actSize);
	return res >= 0 ? actSize : res;
}

int zephyrFlashLock(size_t address, size_t size, enum BootFlashLockType lockType)
{
	if (address + size > CONFIG_ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// round size up to flash block size
	size = size % CONFIG_ROCKETZ_FLASH_BLOCK_SIZE ? size + CONFIG_ROCKETZ_FLASH_BLOCK_SIZE - size % CONFIG_ROCKETZ_FLASH_BLOCK_SIZE : size;
	return lockType == FLASH_LOCK_WRITE ? fprotect_area(address, size) : fprotect_area_no_access(address, size);
}

struct BootFlashDevice flashDevice_internalFlash = {
	.read = zephyrFlashRead,
	.erase = zephyrFlashErase,
	.write = zephyrFlashWrite,
	.lock = zephyrFlashLock,
};

struct BootFlashExtDevice flashDevice_externalFlash = {
	.read = zephyrFlashReadExt,
	.erase = zephyrFlashEraseExt,
	.write = zephyrFlashWriteExt,
	.lock = zephyrFlashLockExt,
};

struct BootFlashDevice *bootInfo_getFlashDevice(enum AppImageStorage storage)
{
	switch (storage)
	{
	case BOOT_IMG_STORAGE_INTERNAL_FLASH:
		return &flashDevice_internalFlash;
		break;

	case BOOT_IMG_STORAGE_EXTERNAL_FLASH:
		return &flashDevice_externalFlash;
		break;

	default:
		return &flashDevice_unknown;
		break;
	}
}

uint32_t wdtChannelCount;
uint32_t wdtTimeout;
uint32_t wdtOptions;
const struct device *wdt_dev;

bool bootloader_isAppSecure()
{
	return true;
}

void bootloader_wdtFeed()
{
	if (wdtChannelCount > 0)
	{
		for (int i = 0; i < wdtChannelCount; i++)
		{
			wdt_feed(wdt_dev, i);
		}
	}
}

#if 0
void k_sys_fatal_error_handler(unsigned int reason, const z_arch_esf_t *esf)
{
#ifdef _DEBUG
	__asm("bkpt");
	while (true)
	{
	}
#endif
	extern void k_sys_fatal_error_handler_mem(unsigned int reason, const z_arch_esf_t *esf);

	k_sys_fatal_error_handler_mem(reason, esf);
}
#endif

void bootloader_restart()
{
	k_msleep(3000);

	// reset the device
	sys_reboot(SYS_REBOOT_COLD);
}

void nrf_cleanup()
{
	nrf_clock_int_disable(NRF_CLOCK, 0xFFFFFFFF);
}

struct wdt_timeout_cfg wdt_settings = {
	.window = {
		.min = 0,
		.max = 1000000},
	.callback = NULL,
	.flags = WDT_FLAG_RESET_SOC,
};

void main(void)
{
	// Setup WDT
	if (((struct BootInfo *)(CONFIG_ROCKETZ_INFO_ADDR))->version == BOOT_VERSION_0_0)
	{
		wdtChannelCount = ((struct BootInfo *)(CONFIG_ROCKETZ_INFO_ADDR))->wdtChannelCount;
		wdtTimeout = ((struct BootInfo *)(CONFIG_ROCKETZ_INFO_ADDR))->wdtTimeout;
		wdtOptions = ((struct BootInfo *)(CONFIG_ROCKETZ_INFO_ADDR))->wdtOptions;

		if (wdtChannelCount > NRF_WDT_CHANNEL_NUMBER)
			wdtChannelCount = NRF_WDT_CHANNEL_NUMBER;

		wdt_settings.window.max = MAX(wdtTimeout, CONFIG_ROCKETZ_WDT_TIMEOUT_MINIMUM);
	}
	else
	{
		wdtChannelCount = 0;
	}

	if (wdtChannelCount > 0)
	{
		int res;

		wdt_dev = device_get_binding(DT_NODE_FULL_NAME(DT_ALIAS(watchdog0)));

		for (uint32_t i = wdtChannelCount; i > 0; i--)
		{
			res = wdt_install_timeout(wdt_dev, &wdt_settings);

			if (res < 0)
			{
				break;
			}

			wdt_feed(wdt_dev, res);
		}

		wdt_setup(wdt_dev, wdtOptions);
	}

#if 0 // For testing. changing WDT timeout

	struct wdt_nrfx_config
	{
		nrfx_wdt_t wdt;
		nrfx_wdt_config_t config;
	};

	wdt_feed(wdt_dev, 0);
	((struct wdt_nrfx_config *)(wdt_dev->config))->window.max = 10000;
#endif

	internalFlashDeviceId = device_get_binding(DT_NODE_FULL_NAME(DT_CHOSEN(zephyr_flash_controller)));
	externalFlashDeviceId = device_get_binding(FLASH_DEVICE);

	bootloader_run();

	// should not reach here
	while (true)
	{
	}
}

struct arm_vector_table
{
	uint32_t msp;
	uint32_t reset;
};

void bootloader_jump(size_t offset)
{
	struct arm_vector_table *vt;

	/* The beginning of the image is the ARM vector table, containing
	 * the initial stack pointer address and the reset vector
	 * consecutively. Manually set the stack pointer and jump into the
	 * reset vector
	 */

	vt = (struct arm_vector_table *)(offset);

	if (IS_ENABLED(CONFIG_SYSTEM_TIMER_HAS_DISABLE_SUPPORT))
	{
		sys_clock_disable();
	}

#if CONFIG_NRF_CLEANUP_PERIPHERAL
	nrf_cleanup();
#endif

#if CONFIG_CLEANUP_ARM_CORE
	cleanup_arm_nvic(); /* cleanup NVIC registers */

#ifdef CONFIG_CPU_CORTEX_M_HAS_CACHE
	/* Disable instruction cache and data cache before chain-load the application */
	SCB_DisableDCache();
	SCB_DisableICache();
#endif

#if CONFIG_CPU_HAS_ARM_MPU || CONFIG_CPU_HAS_NXP_MPU
	z_arm_clear_arm_mpu_config();
#endif

#if defined(CONFIG_BUILTIN_STACK_GUARD) && \
	defined(CONFIG_CPU_CORTEX_M_HAS_SPLIM)
	/* Reset limit registers to avoid inflicting stack overflow on image
	 * being booted.
	 */
	__set_PSPLIM(0);
	__set_MSPLIM(0);
#endif

#else
	irq_lock();
#endif /* CONFIG_CLEANUP_ARM_CORE */

#ifdef CONFIG_BOOT_INTR_VEC_RELOC
#if defined(CONFIG_SW_VECTOR_RELAY)
	_vector_table_pointer = vt;
#ifdef CONFIG_CPU_CORTEX_M_HAS_VTOR
	SCB->VTOR = (uint32_t)__vector_relay_table;
#endif
#elif defined(CONFIG_CPU_CORTEX_M_HAS_VTOR)
	SCB->VTOR = (uint32_t)vt;
#endif /* CONFIG_SW_VECTOR_RELAY */
#else  /* CONFIG_BOOT_INTR_VEC_RELOC */
#if defined(CONFIG_CPU_CORTEX_M_HAS_VTOR) && defined(CONFIG_SW_VECTOR_RELAY)
	_vector_table_pointer = _vector_start;
	SCB->VTOR = (uint32_t)__vector_relay_table;
#endif
#endif /* CONFIG_BOOT_INTR_VEC_RELOC */

	__set_MSP(vt->msp);
#if CONFIG_CLEANUP_ARM_CORE
	__set_CONTROL(0x00); /* application will configures core on its own */
	__ISB();
#endif
	((void (*)(void))vt->reset)();
}