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
	return flash_read(internalFlashDeviceId, address, data, size);
}

int zephyrFlashErase(size_t address, size_t size)
{
	return flash_erase(internalFlashDeviceId, address, size);
}

int zephyrFlashWrite(size_t address, const void *data, size_t size)
{
	// data must be aligned in 4 bytes
	return flash_write(internalFlashDeviceId, address, data, size % 4 ? size + 4 - size % 4 : size);
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

void main(void)
{
	internalFlashDeviceId = device_get_binding(DT_NODE_FULL_NAME(DT_CHOSEN(zephyr_flash_controller)));
	bootloader_run(&flashDevice_internalFlash, &flashDevice_internalFlash);
	while (true)
		;
}

struct signatureDigest
{
	int32_t version;
	char *provider;
	char *userId;
	uint32_t time;
	char *domain;
	char *deviceRole;
	uint32_t size;
	char *sha256;
};

#define DESCR_ARRAY_SIZE 8

struct json_obj_descr descr[DESCR_ARRAY_SIZE] = {
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, version, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, provider, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, userId, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, time, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, domain, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, deviceRole, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, size, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct signatureDigest, sha256, JSON_TOK_STRING),
};

void loadImage(struct ImageInfo *img)
{

	// struct FlashDevice *source = bootInfo_getFlashDevice(img->storage);
	// struct FlashDevice *dest = bootInfo_getFlashDevice(BOOT_IMG_STORAGE_INTERNAL_FLASH);

	// get signature info
	char digestString[512] = "{\n\"version\" : 0,\n\"provider\" : \"zodiac-api\",\n\"userId\" : \"584\",\n\"time\" : 1680531112,\n\"domain\" : \"saar-*\",\n\"deviceRole\" : \"*\",\n\"size\" : 256121,\n\"sha256\" : \"IiSuHNuVCD86YRg5lPAMFrRm8hjIp4jB3jncUhjQHRs=\"\n}";
	struct signatureDigest digest;

	// strcpy(digestString, img->signatureInfo.digest);

	if (json_obj_parse(digestString, strlen(digestString), descr, ARRAY_SIZE(descr), &digest) != ARRAY_SIZE(descr))
	{
		// image_setFlag(img, BOOT_IMG_BAD_SIGNATURE_DIGEST);
		printk("Failed parsing");
	}

	printk("JSON parsed");

	// dest->erase(MAX())

	// 	// erase the flash page
	// 	flash->erase(img->address, img->size);

	// // write the image to flash
	// flash->write(img->address, img->data, img->size);
}

#if ROCKETZ_TEST_APP

#endif