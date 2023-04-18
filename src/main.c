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

#include "rocket-z/bootloader.h"

void loadImage(struct ImageInfo *img);

static const struct device *internalFlashDeviceId;

int zephyrFlashRead(size_t address, void *data, size_t size)
{
	int res = flash_read(internalFlashDeviceId, address, data, size);
	return res >= 0 ? size : res;
}

int zephyrFlashErase(size_t address, size_t size)
{
	return flash_erase(internalFlashDeviceId, address, size);
}

int zephyrFlashWrite(size_t address, const void *data, size_t size)
{
	// data must be aligned in 4 bytes
	int actSize = size % FLASH_WRITE_ALIGNMENT ? size + FLASH_WRITE_ALIGNMENT - size % FLASH_WRITE_ALIGNMENT : size;
	int res = flash_write(internalFlashDeviceId, address, data, actSize);
	return res >= 0 ? actSize : res;
}

int zephyrFlashLock(size_t address, size_t size, enum FlashLockType lockType)
{
	// return flash_write_protection_set(internalFlashDeviceId, true);
}

struct FlashDevice flashDevice_internalFlash = {
	.read = zephyrFlashRead,
	.erase = zephyrFlashErase,
	.write = zephyrFlashWrite,
	.lock = zephyrFlashLock,
};

struct FlashDevice *bootInfo_getFlashDevice(enum ImageStorage storage)
{
	switch (storage)
	{
	case BOOT_IMG_STORAGE_INTERNAL_FLASH:
		return &flashDevice_internalFlash;
		break;

	default:
		return NULL;
		break;
	}
}

void main(void)
{
	internalFlashDeviceId = device_get_binding(DT_NODE_FULL_NAME(DT_CHOSEN(zephyr_flash_controller)));
	bootloader_run(&flashDevice_internalFlash, &flashDevice_internalFlash);
	while (true)
		;
}

#if ROCKETZ_TEST_APP

#endif