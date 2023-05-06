#include "bootloader.h"
#include <string.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/cbc_mode.h>
#include <zephyr/sys/base64.h>

static struct FlashDevice *internalFlash;

static struct BootInfo *bootInfo;

void bootloader_run(struct FlashDevice *_internalFlash, struct FlashDevice *_imageFlash)
{
    internalFlash = _internalFlash;

    bootLogInit(_internalFlash, BOOT_LOG_ADDR);

    bootLog("INFO: Bootloader started");

    bootInfo = bootInfo_load(BOOT_INFO_ADDR);

    if (bootInfo->version != BOOT_VERSION_0_0)
    {
        bootLog("ERROR: Boot info version mismatch");
    }

    // For testing
    appImage_setStore(&bootInfo->img[0], BOOT_IMG_STORAGE_INTERNAL_FLASH, 0x20000, 0x20000);
    appImage_setName(&bootInfo->img[0].imageInfo, "image0");
    appImage_setEncryption(&bootInfo->img[0].imageInfo, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElHbYKCCRqq7Tl7kJrWf+8feaydJoH/SInipkPHoMiljLbo4X8u8oEaDZqmWpXAqN6bhvJYSUL/RpLLKS2kDD5A==", ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, 12032);
    appImage_setSignature(&bootInfo->img[0].imageInfo, "{\"version\":0,\"provider\":\"zodiac\",\"userId\":\"584\",\"time\":1680531112,\"variantPattern\":\"my-product-*:master\",\"size\":12025,\"sha256\":\"BYZX3lDea4TvtBbf8cQQQvrUIEyHoeWA9K9kNuq0o5U=\"}", "MEYCIQD4FqLfB7OzWUlGCEVbSOSoTohLd2fwp8a5VIP01D0NxwIhAPvgxdI2uUPcH/HhndPGbrxpkCRgSE+8K9GdKLoTIrFq");
    appImage_setLoadRequest(&bootInfo->img[0].imageInfo);
    appImage_setValid(&bootInfo->img[0], true);
    bootInfo_setCurrentVariant(bootInfo, "my-product-dev:master");

    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (appImage_hasLoadRequest(&bootInfo->img[i].imageInfo))
        {
            bootLog("INFO: Image %d:%s has load request", i, bootInfo->img[i].imageInfo.imageName);

            // clear load request
            appImage_clearLoadRequest(&bootInfo->img[i].imageInfo);

            // save boot info
            bootInfo_save(BOOT_INFO_ADDR, bootInfo);

            struct SignatureMessage signatureMessage;
            char messageBuff[sizeof(imageInfo->signatureInfo.message)];

            // verify new image
            int verified = appImage_verify(&bootInfo->img[i], bootInfo);

            if (verified < 0)
            {
                bootLog("ERROR: Image %d:%s failed verification. Will not be loaded", i, bootInfo->img[i].imageInfo.imageName);
                continue;
            }

            int res = loadImage(&bootInfo->img[i], bootInfo, &signatureMessage);

            if (res <= 0)
            {
                bootLog("ERROR: Failed to load image %d:%s", i, bootInfo->img[i].imageInfo.imageName);
                continue;
            }

            break;
        }
    }

    // lock memory

    // verify loaded image

    bootInfo_free(bootInfo);

    // run loaded image
}

int loadImage(struct AppImageStore *store, struct BootInfo *bootInfo, struct SignatureMessage *signatureMessage)
{
    bootLog("INFO: Loading image %s", store->imageInfo.imageName);

    if (store->imageInfo.encryption.method != ENCRYPTION_EC_P256_AES_128_CBC_SHA_256)
        return; // no other encryption methods supported yet

    uint8_t prv[32];

    struct
    {
        uint8_t key[16];
        uint8_t iv[16];
    } secret;

    internalFlash->read(BOOT_KEY_ADDR, prv, sizeof(prv));

    int res;

    res = uECC_shared_secret(store->imageInfo.encryption.pubKey, prv, &secret, uECC_secp256r1());

    if (0xFF == prv[0])
    {
        bootLog("WARNING: Private key might have not been stored in flash or is erased");
    }

    // clear prv
    memset(prv, 0x00, sizeof(prv));

    if (res != 1)
    {
        // clear secret
        memset(&secret, 0x00, sizeof(secret));

        bootLog("ERROR: Failed to derive encryption key");

        return -1;
    }

    struct tc_sha256_state_struct digestSha;
    tc_sha256_init(&digestSha);
    tc_sha256_update(&digestSha, &secret, sizeof(secret));
    tc_sha256_final(&secret, &digestSha);

    // Find current image and set rollback image
    for (int i = 0; i < ARRAY_SIZE(bootInfo->img); i++)
    {
        if (bootInfo->img[i].isValid && appImage_isCurrent(&bootInfo->img[i].imageInfo, bootInfo))
        {
            bootLog("INFO: Image %d:%s is selected for rollback", i, bootInfo->img[i].imageInfo.imageName);
            bootInfo->rollbackImageIndex = i;
            break;
        }
    }

    // update currentImage
    memcpy(&bootInfo->currentImage, &store->imageInfo, sizeof(struct AppImageInfo));

    bootInfo_save(BOOT_INFO_ADDR, bootInfo);

    // Erase image area
    res = internalFlash->erase(BOOT_APP_ADDR, MAX(store->imageInfo.encryption.encryptedSize, bootInfo->currentImage.encryption.encryptedSize));

    if (res < 0)
    {
        memset(&secret, 0x00, sizeof(secret));
        bootLog("ERROR: Failed to erase image area");
        return res;
    }

    bootLog("INFO: Starting image transfer");

    // load image

    res = transferToApp(bootInfo_getFlashDevice(store->storage), store->startAddr, store->imageInfo.encryption.encryptedSize, secret.key, secret.iv, signatureMessage);

    if (res < 0)
    {
        memset(&secret, 0x00, sizeof(secret));
        bootLog("ERROR: Failed to load image");
        return res;
    }

    memset(&secret, 0x00, sizeof(secret));

    bootLog("INFO: Image transfer complete");

    return 0;
}

int transferToApp(const struct FlashDevice *device, size_t startAddr, size_t size, const uint8_t *key, const uint8_t *iv)
{
    // one buffer for cipher, decipher including iv

    const size_t blockSize = BOOT_FLASH_BLOCK_SIZE;

    uint8_t buff[blockSize + (2 * TC_AES_BLOCK_SIZE)];

    uint8_t *decipher = buff;
    uint8_t *_iv = buff + TC_AES_BLOCK_SIZE;
    uint8_t *cipher = buff + (2 * TC_AES_BLOCK_SIZE);

    memcpy(_iv, iv, TC_AES_BLOCK_SIZE);

    struct tc_aes_key_sched_struct sched;
    tc_aes128_set_decrypt_key(&sched, key);

    struct tc_sha256_state_struct digestSha;

    tc_sha256_init(&digestSha);

    for (int i = 0; i < size; i += blockSize)
    {
        size_t sizeAct = MIN(blockSize, size - i);

        int res = device->read(startAddr + i, cipher, sizeAct);

        if (res <= 0)
        {
            bootLog("ERROR: Failed to read image data from storage");
            return res;
        }

        res = tc_cbc_mode_decrypt(decipher, sizeAct, cipher, sizeAct, _iv, &sched);

        if (res != 1)
        {
            bootLog("ERROR: Failed to decrypt image data");
            return -1;
        }

        tc_sha256_update(&digestSha, &cipher, MIN(sizeAct, signatureMessage->size - i));

        res = internalFlash->write(BOOT_APP_ADDR + i, decipher, sizeAct);

        if (res <= 0)
        {
            bootLog("ERROR: Failed to write image data");
            return res;
        }

        // copy new initialization vector
        memcpy(_iv, cipher + sizeAct - TC_AES_BLOCK_SIZE, TC_AES_BLOCK_SIZE);
    }

    struct SignatureMessage messageOut;
    char messageBuff[sizeof(store->imageInfo.signatureInfo.message)];

    int res = appImage_getMessageSignature(&store->imageInfo, &messageOut, messageBuff);

    if (res < 0)
    {
        return res;
    }

    uint8_t digest[TC_SHA256_DIGEST_SIZE];
    uint8_t sha[TC_SHA256_DIGEST_SIZE];

    size_t len;

    memset(sha, 0x00, sizeof(sha));

    base64_decode(sha, sizeof(sha), &len, signatureMessage->sha256, strlen(signatureMessage->sha256));

    tc_sha256_final(digest, &digestSha);

    if (memcmp(digest, sha, TC_SHA256_DIGEST_SIZE) != 0)
    {
        bootLog("ERROR: Image hash does not match signature");
        return -1;
    }

    return 0;
}
