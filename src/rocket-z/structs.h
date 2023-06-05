/**
 * \file structs.h
 * \brief Common structs used by the bootloader
 */

#ifndef STRUCTS_H
#define STRUCTS_H

#include "stdint.h"
#include "stdbool.h"
#include "stddef.h"
#include "config.h"
#include <errno.h>

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

enum AppImageHeaderVersion
{
    IMAGE_HEADER_VERSION_0_0 = 0xAB71BE9F, // 0xMINOR_MAJOR
};

enum AppImageEncryptionMethod
{
    ENCRYPTION_NONE = 0,
    ENCRYPTION_EC_P256_AES_128_CBC_SHA_256 = 1,
};

enum BootSignatureVersion
{
    SIGNATURE_VERSION_0_0 = 0x0, // 0xMINOR_MAJOR
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
        char message[CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE];
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

enum BootInfoVersion
{
    BOOT_VERSION_0_0 = 0xF892ACB1, // 0xMINOR_MAJOR
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

/**
 * \brief Image storage information. Includes image information itself.
 */
struct AppImageStore
{
    // Image storage info
    enum AppImageStorage storage; //< Where the image is stored
    size_t startAddr;             //< Address in flash where the image is stored
    size_t maxSize;               //< Maximum size for storage of the image
    uint32_t hasImage;            //< If the store contains a valid image, value should be BOOT_IMG_STORE_VALID

    int32_t loadRequests; //< Inverted bit field of load requests
    int32_t loadAttempts; //< Inverted bit field of load attempts
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

#endif // STRUCTS_H