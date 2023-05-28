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
#include "rocket-z/config.h"

#include "arm_cleanup.h"

#include "rocket-z/bootloader.h"

static const struct device *internalFlashDeviceId;

int zephyrFlashRead(size_t address, void *data, size_t size)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
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
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_INVALID_ADDRESS;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// allign the erase region with the ROCKETZ_FLASH_BLOCK_SIZE
	size = size % ROCKETZ_FLASH_BLOCK_SIZE ? size + ROCKETZ_FLASH_BLOCK_SIZE - size % ROCKETZ_FLASH_BLOCK_SIZE : size;
	return flash_erase(internalFlashDeviceId, address, size);
}

int zephyrFlashWrite(size_t address, const void *data, size_t size)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_INVALID_ADDRESS;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// data must be aligned in 4 bytes
	int actSize = size % ROCKETZ_FLASH_WRITE_ALIGNMENT ? size + ROCKETZ_FLASH_WRITE_ALIGNMENT - size % ROCKETZ_FLASH_WRITE_ALIGNMENT : size;
	int res = flash_write(internalFlashDeviceId, address, data, actSize);
	return res >= 0 ? actSize : res;
}

int zephyrFlashLock(size_t address, size_t size, enum BootFlashLockType lockType)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return BOOT_ERROR_MEMORY_LOCKED;
	}

	// round size up to flash block size
	size = size % ROCKETZ_FLASH_BLOCK_SIZE ? size + ROCKETZ_FLASH_BLOCK_SIZE - size % ROCKETZ_FLASH_BLOCK_SIZE : size;
	return lockType == FLASH_LOCK_WRITE ? fprotect_area(address, size) : fprotect_area_no_access(address, size);
}

struct BootFlashDevice flashDevice_internalFlash = {
	.read = zephyrFlashRead,
	.erase = zephyrFlashErase,
	.write = zephyrFlashWrite,
	.lock = zephyrFlashLock,
};

struct BootFlashDevice *bootInfo_getFlashDevice(enum AppImageStorage storage)
{
	switch (storage)
	{
	case BOOT_IMG_STORAGE_INTERNAL_FLASH:
		return &flashDevice_internalFlash;
		break;

	default:
		return &flashDevice_unknown;
		break;
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

#include <nrfx_gpiote.h>

void bootloader_restart()
{
	nrfx_gpiote_out_config_t out_config = {
		.action = NRF_GPIOTE_POLARITY_LOTOHI,
		.init_state = 1,
		.task_pin = false,
	};
	nrfx_gpiote_out_init(13, &out_config);

	while (true)
	{
		nrfx_gpiote_out_toggle(13);
		k_msleep(500);
	}
}

void nrf_cleanup()
{
	nrf_clock_int_disable(NRF_CLOCK, 0xFFFFFFFF);
}

void main(void)
{

	internalFlashDeviceId = device_get_binding(DT_NODE_FULL_NAME(DT_CHOSEN(zephyr_flash_controller)));

	// lock bootloadaer memory
	int res = zephyrFlashLock(0x0, ROCKETZ_BOOTLOADER_SIZE_MAX, FLASH_LOCK_WRITE);

	if (res < 0)
	{
		bootLog("ERROR: Failed to lock boot area.");
		bootloader_restart();
	}

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