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
#include <errno.h>

#ifndef ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
#define ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE 512
#endif

    enum BootError
    {
        BOOT_ERROR_SUCCESS = 0,
        BOOT_ERROR_UNKNOWN = -2000,
        BOOT_ERROR_SIGNATURE_MESSAGE_INVALID = -6002,
        BOOT_ERROR_AUTHENTICATOR_HAS_LIMITED_PERMISSIONS = -6003,
        BOOT_ERROR_NO_AUTHENTICATOR = -6004,
        BOOT_ERROR_INVALID_SIGNATURE = -6005,
        BOOT_ERROR_INVALID_SIZE = -6006,
        BOOT_ERROR_FAILED_PARSE = -6007,
        BOOT_ERROR_FAILED_CHECKSUM = -6008,
        BOOT_ERROR_INVALID_HEADER_VERSION = -6009,
        BOOT_ERROR_UNSUPPORTED_ENCRYPTION_METHOD = -6010,
        BOOT_ERROR_APP_IMAGE_NOT_VALID = -6012,
        BOOT_ERROR_UNKNOWN_DEVICE = -ENODEV,
        BOOT_ERROR_MEMORY_LOCKED = -EACCES,
        BOOT_ERROR_BAD_ARGUMENT = -EINVAL,
        BOOT_ERROR_INVALID_ADDRESS = -EFAULT,
        BOOT_ERROR_NOT_IMPLEMENTED = -ENOSYS,
        BOOT_ERROR_NOT_SUPPORTED = -ENOTSUP,
        BOOT_ERROR_TOO_LARGE = -EOVERFLOW,
    };

    enum BootFlashLockType
    {
        FLASH_LOCK_READ = 1 << 0,
        FLASH_LOCK_WRITE = 1 << 1,
        FLASH_LOCK_ALL = FLASH_LOCK_READ | FLASH_LOCK_WRITE,
    };

    struct BootFlashDevice
    {
        int (*read)(size_t address, void *data, size_t size);
        int (*erase)(size_t address, size_t size);
        int (*write)(size_t address, const void *data, size_t size);
        int (*lock)(size_t address, size_t size, enum BootFlashLockType lockType); //< Optional. If not provided, will be used for internal flash only.
    };

    extern struct BootFlashDevice flashDevice_unknown;

    enum AppImageHeaderVersion
    {
        IMAGE_HEADER_VERSION_0_0 = 0xAB71BE9F, // 0xMINOR_MAJOR
    };

    enum AppImageEncryptionMethod
    {
        ENCRYPTION_EC_P256_AES_128_CBC_SHA_256 = 1,
    };

    enum BootSignatureVersion
    {
        SIGNATURE_VERSION_0_0 = 0x0, // 0xMINOR_MAJOR
    };

    enum AppImageStorage
    {
        BOOT_IMG_STORAGE_INTERNAL_FLASH = 0x819b,
        BOOT_IMG_STORAGE_EXTERNAL_FLASH = 0x96f3,
    };

    enum AppImageStoreState
    {
        BOOT_IMG_STORE_VALID = 0x0f2d3c4b,
    };

#pragma pack(4)
    /**
     * \brief Image information
     */
    struct AppImageHeader
    {
        uint32_t headerVersion; //< AppImageHeaderVersion

        uint32_t headerSize; //< This header size. Some devices have limitation and it needs to be a multiple of some number (e.g. 10124 for nRF)

        char imageName[64]; //< Firendly image name. preferablly unique.

        // Image encryption info
        struct
        {
            int32_t method;
            uint32_t encryptedSize;
            uint32_t pubKeyCrc32; //< Optional CRC32-IEEE of Rocket bootloader public key. Used to verify that the bootloader is compatible with the image.
            uint8_t pubKey[64];   //< Author's public key used for encryption. Base 64 encoded.
        } encryption;

        // signature info
        struct
        {
            uint32_t signatureVersion;
            uint8_t signature[64];
            /**
             * \brief Digest message as a JSON string. See SignatureMessage struct for details.
             * example:
             * {
                    "version": 0,
                    "authenticator": "zodiac-api",
                    "userId": "584",
                    "time": 1680531112,
                    "variantPattern": "my-product-*:master",
                    "size": 256121,
                    "sha256": "IiSuHNuVCD86YRg5lPAMFrRm8hjIp4jB3jncUhjQHRs="
                }
            */
            char message[ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];
        } signatureInfo;
    };

    struct AppImageSignatureMessage
    {
        char *authenticator;
        char *authorId;
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
        uint32_t hasImage;            //< Is the store contains a valid image

        int32_t loadRequests; //< Inverted bit field of load requests
        int32_t loadAttempts; //< Inverted bit field of load attempts
    };

    enum BootInfoVersion
    {
        BOOT_VERSION_0_0 = 0xF892ACB1, // 0xMINOR_MAJOR
    };

    /**
     * \brief Bootloader information
     */
    struct BootInfo
    {
        uint32_t version;              //< Struct version
        char bootloaderName[32];       //< Friendly bootloader name
        char currentVariant[100];      //< Current variant name
        uint8_t rollbackImageIndex;    //< Index of the image to rollback to
        struct AppImageStore appStore; //< Information about the currently loaded image
        uint32_t failCountMax;         //< Maximum number of times to run the image before marking it as invalid
        uint32_t failFlags;            //< Inverted bit field of fail marks
        uint32_t failClears;
        uint8_t noLockCode[32];   //< Passcode used to prevent the bootloader from locking memory
        uint32_t wdtTimeout;      //< Watchdog timeout in milliseconds
        uint32_t wdtChannelCount; //< Number of watchdog channels
        uint32_t wdtOptions;      //< Device-specific watchdog options.

        struct AppImageStore stores[4];
    };
    /**
     * \brief Bootloader information buffer. Contains BootInfo and a copy of the original BootInfo.
     */
    struct BootInfoBuffer
    {
        struct BootInfo bootInfo;
        struct BootInfo bootInfo_orig;
    };

    /**
     * \brief Get the flash device used to store images or boot info. Must be implemented externally.
     * \param storage Storage type
     */
    struct BootFlashDevice *bootInfo_getFlashDevice(enum AppImageStorage storage);

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
     * \param buff Pointer to the boot information structure output
     * \return Pointer to the boot information structure. Null if the boot information is invalid.
     */
    struct BootInfo *bootInfo_load(uint32_t address, struct BootInfoBuffer *buff);

    /**
     * \brief Save boot information to flash if it has changed
     * \param address Address in flash where the boot information is stored
     * \param info Pointer to the boot information structure buffer
     * \return 0 on success, BootError on error
     */
    enum BootError bootInfo_save(uint32_t address, const struct BootInfoBuffer *info);

    /**
     * \brief Check if image is the one currently loaded
     * \param header Pointer to the image header structure
     * \param bootInfo Pointer to the boot information structure
     * \return true if image is the one currently loaded, false otherwise
     */
    bool appImage_isCurrent(const struct AppImageHeader *header, const struct BootInfo *bootInfo);

    /**
     * \brief Set image address in images store flash
     * \param info Pointer to the image information structure
     * \param type Where the image is stored
     * \param offset Address in flash where the image is stored. must point to image header.
     * \param maxSize Maximum size for storage location
     */
    void bootInfo_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize);

    /**
     * \brief Set whethre a store has a valid image
     * \param store Pointer to the image store struct
     * \param status target status
     */
    void bootInfo_setHasImage(struct AppImageStore *store, bool hasImage);

    /**
     * \brief Check if store contains image data
     * \param store Pointer to the image store struct
     * \return true if image is valid, false otherwise
     */
    bool bootInfo_hasImage(const struct AppImageStore *store);

    /**
     * \brief Set currently-running image variant name
     * \param info Pointer to the image information structure
     * \param variant Image variant information.
     * \return 0 on success, BootError on error
     */
    enum BootError bootInfo_setCurrentVariant(struct BootInfo *store, const char *variant);

    /**
     * \brief Mark image to be loaded
     * \param store Pointer to store information structure
     */
    void bootInfo_setLoadRequest(struct AppImageStore *store);

    /**
     * \brief Clear image load request
     * \param store Pointer to store information structure
     */
    void bootInfo_clearLoadRequest(struct AppImageStore *store);

    /**
     * \brief Check if image has a load request
     * \param store Pointer to store information structure
     * \return true if image has a load request, false otherwise
     */
    bool bootInfo_hasLoadRequest(const struct AppImageStore *store);

    /**
     * \brief Read image header from flash
     * \param header Pointer to the image header structure
     * \param store Pointer to the image information structure
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_readHeader(struct AppImageHeader *header, const struct AppImageStore *store);

    /**
     * \brief Check if image signature is valid
     * \param header Pointer to the image header structure
     * \return 0 if verified, BootError otherwise
     */
    enum BootError appImage_verifySignature(const struct AppImageHeader *header);

    /**
     * \brief Performs multiple checks to verify that the image is loadable. Includes signature verification.
     * \param imageStore Pointer to the image information structure
     * \param bootInfo Optional. Pointer to the boot information structure. If not NULL a warning will be logged if the given image doesn't have a matching variant to current one.
     * \return 0 if verified, BootError otherwise
     */
    enum BootError appImage_verify(const struct AppImageStore *imageStore, const struct BootInfo *bootInfo);

    /**
     * \brief Perfrom checksum on image. It can only be done in the bootloader as it requires decrypting the image.
     * \param store Pointer to the image store
     * \return 0 if checksum matches signature, BootError on error
     */
    enum BootError appImage_verifyChecksum(const struct AppImageStore *store);

    /**
     * \brief Transfer an image from one store to another. If the destination is the app area image will be decrypted, if the source is the app area image will be encrypted.
     * \param fromStore Pointer to the source image store
     * \param toStore Pointer to the destination image store
     * \param bootInfoBuff Optional. Pointer to the boot information structure. if not NULL bootInfo will be saved automatically.
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_transfer(const struct AppImageStore *fromStore, struct AppImageStore *toStore, struct BootInfoBuffer *bootInfoBuff);

    /**
     * \brief Get fail count
     * \param info Pointer to the boot information structure
     */
    uint32_t bootInfo_getFailCount(const struct BootInfo *info);

    /**
     * \brief Raise fail flag for the currently running image. occurs normally before the app runs.
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failFlag(struct BootInfo *info);

    /**
     * \brief Clear fail flag for the currently running image. Must be called by the app to indicate that it has run successfully.
     * \param info Pointer to the boot information structure
     */
    void bootInfo_failClear(struct BootInfo *info);

    /**
     * \brief Set image name
     * \param header Pointer to the image header structure
     * \param name Image name
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_setName(struct AppImageHeader *header, const char *name);

    /**
     * \brief Set image header version and size
     * \param header Pointer to the image header structure
     * \param version Image header version
     * \param size Image header size
     */
    void appImage_setHeader(struct AppImageHeader *header, enum AppImageHeaderVersion version, size_t size);

    /**
     * \brief Set encryption information for an image
     * \param header Pointer to the image header structure
     * \param pubKey Public key used for encryption. PEM-formatted. With or without header and footer.
     * \param method Encryption method
     * \param encryptedSize Size of the encrypted image
     * \param pubKeyCrc32 Optional CRC32-IEEE of Rocket bootloader public key.
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_setEncryption(struct AppImageHeader *header, const char *pubKey, enum AppImageEncryptionMethod method, size_t encryptedSize, uint32_t pubKeyCrc32);

    /**
     * Set signature information for an image
     * \param header Pointer to the image header structure
     * \param message Digest message as a JSON string
     * \param signature Signature of the message. PEM-formatted. With or without header and footer.
     * \param signatureVersion Signature version
     * \return 0 on success, BootError on error
     */
    enum BootError appImage_setSignature(struct AppImageHeader *header, const char *message, const char *signature, enum BootSignatureVersion signatureVersion);

    /**
     * \brief Get the signature message data for an image
     * \param header Pointer to the image header structure
     * \param messageOut Pointer to the output of signature message data.
     * \param messageBuff A buffer where message strings are stored. Must be at least of size ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
     * \return 0 on success, BootError otherwise
     */
    enum BootError appImage_getSignatureMessage(const struct AppImageHeader *header, struct AppImageSignatureMessage *messageOut, char *messageBuff);

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
     * \return 0 on success, BootError on error
     */
    enum BootError bootLogInit(const struct BootFlashDevice *flash, uint32_t address);

#ifdef __cplusplus
}
#endif

#endif /* CONTROLLER_H_ */