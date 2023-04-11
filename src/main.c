/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/data/json.h>
#include "string.h"

#include "rocket-z/controller.h"

#ifndef BOOT_INFO_ADDR
#define BOOT_INFO_ADDR (0xC000 - FLASH_BLOCK_SIZE) // 0xB000. 0xC000 is the typical start of app. 0x1000 is the typical flash block size
#endif

#ifndef BOOT_LOG_ADDR
#define BOOT_LOG_ADDR (0xC000 - (2 * FLASH_BLOCK_SIZE)) // 0xA000. 0xC000 is the typical start of app.
#endif

void loadImage(struct ImageInfo *img);

void main(void)
{
	bootLogInit(, BOOT_LOG_ADDR);
	loadImage(BOOT_INFO_ADDR);

	// struct BootInfo *bootInfo = bootInfo_load(BOOT_INFO_ADDR);

	// for (int i = 0; i < 2; i++)
	// {
	// 	if (!image_getFlag(bootInfo->img[i], BOOT_IMG_INVALID) && image_getFlag(bootInfo->img[i], BOOT_IMG_REQUESTED))
	// 	{
	// 		if (loadImage(BOOT_INFO_ADDR))
	// 	}
	// }

	// bootInfo->img[0].status = 0;
	// image_setFlag(&bootInfo->img[0], BOOT_IMG_REQUESTED);

	// bootInfo_save(0x0000, bootInfo);
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