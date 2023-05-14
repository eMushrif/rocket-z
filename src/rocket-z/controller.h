/**
 * \file controller.h
 * \brief Provides functions to manage images and initiate DFU
 */

#ifndef CONTROLLER_H
#define CONTROLLER_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "stdint.h"
#include "stdbool.h"
#include "stddef.h"
#include <stdlib.h>
#include <zephyr/kernel.h>

#ifndef BOOT_FLASH_BLOCK_SIZE
#define BOOT_FLASH_BLOCK_SIZE 0x1000
#endif

#ifndef BOOT_FLASH_WRITE_ALIGNMENT
#define BOOT_FLASH_WRITE_ALIGNMENT 4
#endif

#ifndef BOOT_APP_ADDR
#define BOOT_APP_ADDR 0x10000
#endif

#ifndef BOOT_MAX_APPIMAGE_SIZE
#define BOOT_MAX_APPIMAGE_SIZE (0x100000 - BOOT_APP_ADDR) // 1MB - Bootloder size
#endif

#ifndef BOOT_INFO_ADDR
#define BOOT_INFO_ADDR (BOOT_APP_ADDR - BOOT_FLASH_BLOCK_SIZE)
#endif

#ifndef BOOT_LOG_ADDR
#define BOOT_LOG_ADDR (BOOT_APP_ADDR - (2 * BOOT_FLASH_BLOCK_SIZE))
#endif

#ifndef BOOT_KEY_ADDR
#define BOOT_KEY_ADDR (BOOT_APP_ADDR - (3 * BOOT_FLASH_BLOCK_SIZE))
#endif

#ifndef BOOT_SIGNATURE_MESSAGE_MAX_SIZE
#define BOOT_SIGNATURE_MESSAGE_MAX_SIZE 512
#endif

    enum BootError
    {
        BOOT_ERROR_SUCCESS = 0,
        BOOT_ERROR_APP_IMAGE_NOT_VALID = -1,
        BOOT_ERROR_SIGNATURE_MESSAGE_INVALID = -2,
        BOOT_ERROR_SIGNER_HAS_LIMITED_PERMISSIONS = -3,
        BOOT_ERROR_UNKNOWN_SIGNER = -4,
        BOOT_ERROR_INVALID_SIGNATURE = -5,
        BOOT_ERROR_INVALID_SIZE = -6,
        BOOT_ERROR_FAILED_PARSE = -7,
        BOOT_ERROR_FAILED_CHECKSUM = -8,
        BOOT_ERROR_INVALID_HEADER_VERSION = -9,
        BOOT_ERROR_UNSUPPORTED_ENCRYPTION_METHOD = -10,
    };

    enum FlashLockType
    {
        FLASH_LOCK_READ = 1 << 0,
        FLASH_LOCK_WRITE = 1 << 1,
        FLASH_LOCK_ALL = FLASH_LOCK_READ | FLASH_LOCK_WRITE,
    };

    struct FlashDevice
    {
        int (*read)(size_t address, void *data, size_t size);
        int (*erase)(size_t address, size_t size);
        int (*write)(size_t address, const void *data, size_t size);
        int (*lock)(size_t address, size_t size, enum FlashLockType lockType); //< Optional. If not provided, will be used for internal flash only.
    };

    enum AppImageHeaderVersion
    {
        IMAGE_HEADER_VERSION_0_0 = 0xAB71BE9F,
    };

    enum AppImageEncryptionMethod
    {
        ENCRYPTION_EC_P256_AES_128_CBC_SHA_256 = 1,
    };

    enum AppImageStorage
    {
        BOOT_IMG_STORAGE_EXTERNAL_FLASH = 0,
        BOOT_IMG_STORAGE_INTERNAL_FLASH,
    };

#pragma pack(4)
    /**
     * \brief Image information
     */
    struct AppImageHeader
    {
        uint32_t headerVersion; //< AppImageHeaderVersion

        uint32_t headerSize;

        char imageName[64]; //< Firendly image name. preferablly unique.

        // Image encryption info
        struct
        {
            int32_t method;
            uint32_t encryptedSize;
            uint8_t pubKey[64]; //< Public key used for encryption. Base 64 encoded.
        } encryption;

        // signature info
        struct
        {
            uint8_t signature[64];
            /**
             * \brief Digest message as a JSON string. See SignatureMessage struct for details.
             * example:
             * {
                    "version": 0,
                    "provider": "zodiac-api",
                    "userId": "584",
                    "time": 1680531112,
                    "variantPattern": "my-product-*:master",
                    "size": 256121,
                    "sha256": "IiSuHNuVCD86YRg5lPAMFrRm8hjIp4jB3jncUhjQHRs="
                }
            */
            char message[BOOT_SIGNATURE_MESSAGE_MAX_SIZE];
        } signatureInfo;
    };

    struct SignatureMessage
    {
        int32_t version;
        char *provider;
        char *userId;
        uint32_t time;
        char *variantPattern;
        uint32_t size;
        char *sha256;
    };

    /**
     * \brief Image storage information. Includes image information itself.
     */
    struct AppImageStore
    {
        // Image storage info
        enum AppImageStorage storage; //< Where the image is stored
        size_t startAddr;             //< Address in flash where the image is stored
        size_t maxSize;               //< Maximum size for storage of the image
        bool isValid;                 //< Is the image stored valid

        int32_t loadRequests; //< Inverted bit field of load requests
        int32_t loadAttempts; //< Inverted bit field of load attempts
    };

    enum BootInfoVersion
    {
        BOOT_VERSION_0_0 = 0xF892,
    };

    /**
     * \brief Bootloader information
     */
    struct BootInfo
    {
        int version; //< Struct version

        char bootloaderName[32]; //< Friendly bootloader name

        char currentVariant[100]; //< Current variant name

        uint8_t rollbackImageIndex; //< Index of the image to rollback to

        struct AppImageStore appStore; //< Information about the currently loaded image

        uint32_t failCountMax; //< Maximum number of times to run the image before marking it as invalid

        uint32_t failFlags; //< Inverted bit field of fail marks
        uint32_t failClears;

        struct AppImageStore stores[4];
    };

    /**
     * \brief Get the flash device used to store images or boot info. Must be implemented externally.
     * \param storage Storage type
     */
    struct FlashDevice *bootInfo_getFlashDevice(enum AppImageStorage storage);

    /**
     * \brief Generate random bytes. Must be implemented externally.
     * \param data Buffer to store the random bytes
     * \param size Number of bytes to generate
     * \return 0 on success, -1 on error
     */
    int bootInfo_rng(uint8_t *data, size_t size);

    /**
     * \brief Load boot information from flash
     * \param address Address in flash where the boot information is stored
     * \param info Pointer to the boot information structure output
     * \return Pointer to the boot information structure. Null if the boot information is invalid.
     */
    struct BootInfo *bootInfo_load(uint32_t address, struct BootInfo *info);

    /**
     * \brief Save boot information to flash if it has changed
     * \param address Address in flash where the boot information is stored
     * \param info Pointer to the boot information structure
     */
    void bootInfo_save(uint32_t address, const struct BootInfo *info);

    /**
     * \brief Set image address in images store flash
     * \param info Pointer to the image information structure
     * \param type Where the image is stored
     * \param offset Address in flash where the image is stored. must point to image header.
     * \param maxSize Maximum size for storage location
     */
    void appImage_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize);

    /**
     * \brief Set image valid status
     * \param info Pointer to the image store struct
     * \param valid Valid status
     */
    void appImage_setValid(struct AppImageStore *info, bool valid);

    /**
     * \brief Set currently-running image variant name
     * \param info Pointer to the image information structure
     * \param variant Image variant information.
     */
    void bootInfo_setCurrentVariant(struct BootInfo *store, const char *variant);

    /**
     * \brief Mark image to be loaded
     * \param store Pointer to store information structure
     */
    void appImage_setLoadRequest(struct AppImageStore *store);

    /**
     * \brief Clear image load request
     * \param store Pointer to store information structure
     */
    void appImage_clearLoadRequest(struct AppImageStore *store);

    /**
     * \brief Check if image has a load request
     * \param store Pointer to store information structure
     * \return true if image has a load request, false otherwise
     */
    bool appImage_hasLoadRequest(struct AppImageStore *store);

    /**
     * \brief Read image header from flash
     * \param header Pointer to the image header structure
     * \param store Pointer to the image information structure
     * \return 0 on success, BootError on error
     */
    int appImage_readHeader(struct AppImageHeader *header, const struct AppImageStore *store);

    /**
     * \brief Check if image signature is valid
     * \param header Pointer to the image header structure
     * \return 0 if verified, BootError otherwise
     */
    int appImage_verifySignature(const struct AppImageHeader *header);

    /**
     * \brief Performs multiple checks to verify that the image is loadable. Includes signature verification.
     * \param imageStore Pointer to the image information structure
     * \param bootInfo Pointer to the boot information structure
     * \return 0 if verified, BootError otherwise
     */
    int appImage_verify(const struct AppImageStore *imageStore, const struct BootInfo *bootInfo);

    /**
     * \brief Perfrom checksum on image
     * \param store Pointer to the image store
     * \return 0 if checksum matches signature, BootError on error
     */
    int appImage_verifyChecksum(const struct AppImageStore *store);

    /**
     * \brief Transfer an image from one store to another. If the destination is the app area image will be decrypted, if the source is the app area image will be encrypted.
     * \param fromStore Pointer to the source image store
     * \param toStore Pointer to the destination image store
     * \param bootInfo Optional. Pointer to the boot information structure. if not NULL bootInfo will be saved automatically.
     * \return 0 on success, BootError on error
     */
    int appImage_transfer(struct AppImageStore *fromStore, struct AppImageStore *toStore, struct BootInfo *bootInfo);

    /**
     * \brief Get fail count
     * \param info Pointer to the boot information structure
     */
    uint32_t bootInfo_getFailCount(const struct BootInfo *info);

    /**
     * \brief raise fail flag for the currently running image
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failFlag(struct BootInfo *info);

    /**
     * \brief clear fail flag for the currently running image
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failClear(struct BootInfo *info);

    /**
     * \brief Set encryption information for an image
     * \param header Pointer to the image header structure
     * \param pubKey Public key used for encryption. PEM-formatted. With or without header and footer.
     * \param encryptedSize Size of the encrypted image
     * \param method Encryption method
     */
    enum BootError appImage_setEncryption(struct AppImageHeader *header, const char *pubKey, enum AppImageEncryptionMethod method, size_t encryptedSize);

    /**
     * Set signature information for an image
     * \param header Pointer to the image header structure
     * \param message Digest message as a JSON string
     * \param signature Signature of the message. PEM-formatted. With or without header and footer.
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_setSignature(struct AppImageHeader *header, const char *message, const char *signature);

    /**
     * \brief Get the signature message data for an image
     * \param header Pointer to the image header structure
     * \param messageOut Pointer to the output of signature message data.
     * \param messageBuff A buffer where message strings are stored. Must be at least of size BOOT_SIGNATURE_MESSAGE_MAX_SIZE
     * \return 0 if verified, BootError otherwise
     */
    int appImage_getSignatureMessage(const struct AppImageHeader *header, struct SignatureMessage *messageOut, char *messageBuff);

    /**
     * \brief Check if image is the one currently loaded
     * \param header Pointer to the image header structure
     * \param bootInfo Pointer to the boot information structure
     * \return true if image is the one currently loaded, false otherwise
     */
    bool appImage_isCurrent(struct AppImageStore *store, struct BootInfo *bootInfo);

    /**
     * \brief Set image name
     * \param header Pointer to the image header structure
     * \param name Image name
     */
    void appImage_setName(struct AppImageHeader *header, const char *name);

    /**
     * \brief Log event
     * \param fmt Format string. similar to printf
     * \param ... Format arguments
     */
    void bootLog(const char *fmt, ...);

    /**
     * \brief Initialize the boot log
     * \param flash Flash device used to store the log
     * \param address Address in flash where the log is stored
     */
    void bootLogInit(struct FlashDevice *flash, uint32_t address);

#ifdef __cplusplus
}
#endif

#endif /* CONTROLLER_H_ */