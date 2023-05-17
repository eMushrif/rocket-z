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

#include "rocket-z/bootloader.h"

static const struct device *internalFlashDeviceId;

int zephyrFlashRead(size_t address, void *data, size_t size)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return -EINVAL;
	}

	if (fprotect_is_protected(address) & 2)
	{
		return -EPERM;
	}

	int res = flash_read(internalFlashDeviceId, address, data, size);
	return res >= 0 ? size : res;
}

int zephyrFlashErase(size_t address, size_t size)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return -EINVAL;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return -EPERM;
	}

	// allign the erase region with the ROCKETZ_FLASH_BLOCK_SIZE
	size = size % ROCKETZ_FLASH_BLOCK_SIZE ? size + ROCKETZ_FLASH_BLOCK_SIZE - size % ROCKETZ_FLASH_BLOCK_SIZE : size;
	return flash_erase(internalFlashDeviceId, address, size);
}

int zephyrFlashWrite(size_t address, const void *data, size_t size)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return -EINVAL;
	}

	if (fprotect_is_protected(address) & 1)
	{
		return -EPERM;
	}

	// data must be aligned in 4 bytes
	int actSize = size % ROCKETZ_FLASH_WRITE_ALIGNMENT ? size + ROCKETZ_FLASH_WRITE_ALIGNMENT - size % ROCKETZ_FLASH_WRITE_ALIGNMENT : size;
	int res = flash_write(internalFlashDeviceId, address, data, actSize);
	return res >= 0 ? actSize : res;
}

int zephyrFlashLock(size_t address, size_t size, enum FlashLockType lockType)
{
	if (address + size > ROCKETZ_INTERNAL_FLASH_SIZE)
	{
		return -EINVAL;
	}

	// round size up to flash block size
	size = size % ROCKETZ_FLASH_BLOCK_SIZE ? size + ROCKETZ_FLASH_BLOCK_SIZE - size % ROCKETZ_FLASH_BLOCK_SIZE : size;
	return lockType == FLASH_LOCK_WRITE ? fprotect_area(address, size) : fprotect_area_no_access(address, size);
}

struct FlashDevice flashDevice_internalFlash = {
	.read = zephyrFlashRead,
	.erase = zephyrFlashErase,
	.write = zephyrFlashWrite,
	.lock = zephyrFlashLock,
};

struct FlashDevice *bootInfo_getFlashDevice(enum AppImageStorage storage)
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

void main(void)
{

	internalFlashDeviceId = device_get_binding(DT_NODE_FULL_NAME(DT_CHOSEN(zephyr_flash_controller)));

	bootloader_run(&flashDevice_internalFlash, &flashDevice_internalFlash);

	// should not reach here
	while (true)
		;
}

#if ROCKETZ_TEST_APP

#endif