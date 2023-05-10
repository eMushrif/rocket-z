/**
 * \file controller.h
 * \brief Provides functions to manage images and initiate DFU
 */

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
#define BOOT_APP_ADDR 0xF000 // 0xC000 is the typical start of app.
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
    BOOT_ERROR_appImage_NOT_VALID = -1,
    BOOT_ERROR_SIGNATURE_MESSAGE_INVALID = -2,
    BOOT_ERROR_SIGNER_HAS_LIMITED_PERMISSIONS = -3,
    BOOT_ERROR_UNKNOWN_SIGNER = -4,
    BOOT_ERROR_INVALID_SIGNATURE = -5,
    BOOT_ERROR_INVALID_SIZE = -6,
    BOOT_ERROR_FAILED_PARSE = -7,
    BOOT_ERROR_FAILED_CHECKSUM = -8,
};

enum FlashLockType
{
    FLASH_LOCK_READ = 1 << 0,
    FLASH_LOCK_WRITE = 1 << 1,
    FLASH_LOCK_ERASE = 1 << 2,
    FLASH_LOCK_ALL = FLASH_LOCK_READ | FLASH_LOCK_WRITE | FLASH_LOCK_ERASE,
};

struct FlashDevice
{
    int (*read)(size_t address, void *data, size_t size);
    int (*erase)(size_t address, size_t size);
    int (*write)(size_t address, const void *data, size_t size);
    int (*lock)(size_t address, size_t size, enum FlashLockType lockType); //< Optional. If not provided, will be used for internal flash only.
};

enum EncryptionMethod
{
    ENCRYPTION_EC_P256_AES_128_CBC_SHA_256 = 1,
};

enum AppImageStatus
{
    BOOT_IMG_REQUESTED = 1 << 0,    //< request loading this image. setting this flag resets all other flags and BOOT_IMG_INVALID
    BOOT_IMG_LOAD_ATTEMPT = 1 << 2, //< an attempt to load this image was made
    BOOT_IMG_INVALID = 1 << 8,      //< image was invalidated and will not be loaded. Changing other image flags will not set this flag.
};

enum AppImageStorage
{
    BOOT_IMG_STORAGE_EXTERNAL_FLASH = 0,
    BOOT_IMG_STORAGE_INTERNAL_FLASH,
};

/**
 * \brief Image information
 */
struct AppImageInfo
{
    char imageName[64]; //< Firendly image name. preferablly unique.

    int32_t strikeCountResetVal;

    int32_t loadRequests; //< Inverted bit field of load requests
    int32_t loadAttempts; //< Inverted bit field of load attempts

    // Image encryption info
    struct
    {
        int32_t method;
        uint8_t pubKey[64]; //< Public key used for encryption. Base 64 encoded.
        uint32_t encryptedSize;
    } encryption;

    // signature info
    struct
    {

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
        uint8_t signature[64];
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

    struct AppImageInfo imageInfo; //< Image information
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

    struct AppImageStore img[3];
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
 * \return Pointer to the boot information structure. Null if the boot information is invalid.
 */
struct BootInfo *bootInfo_load(uint32_t address);

/**
 * \brief Save boot information to flash if it has changed
 * \param address Address in flash where the boot information is stored
 * \param info Pointer to the boot information structure
 */
void bootInfo_save(uint32_t address, const struct BootInfo *info);

/**
 * \brief Free boot information structure
 * \param info Pointer to the boot information structure
 */
void bootInfo_free(struct BootInfo *info);

/**
 * \brief Set image name
 * \param info Pointer to the image information structure
 * \param name Image name
 */
void appImage_setName(struct AppImageInfo *info, const char *name);

/**
 * \brief Set image address in images store flash
 * \param info Pointer to the image information structure
 * \param type Where the image is stored
 * \param offset Address in flash where the image is stored
 * \param maxSize Maximum size for storage location
 */
void appImage_setStore(struct AppImageStore *info, enum AppImageStorage storage, size_t offset, size_t maxSize);

/**
 * \brief Set encryption information for an image
 * \param info Pointer to the image information structure
 * \param pubKey Public key used for encryption. PEM-formatted. With or without header and footer.
 * \param encryptedSize Size of the encrypted image
 * \param method Encryption method
 */
enum BootError appImage_setEncryption(struct AppImageInfo *info, const char *pubKey, enum EncryptionMethod method, size_t encryptedSize);

/**
 * Set signature information for an image
 * \param info Pointer to the image information structure
 * \param message Digest message as a JSON string
 * \param signature Signature of the message. PEM-formatted. With or without header and footer.
 * \return 0 on success, BootError on error
 */
enum BootError appImage_setSignature(struct AppImageInfo *info, const char *message, const char *signature);

/**
 * \brief Set image valid status
 * \param info Pointer to the image store struct
 * \param valid Valid status
 */
void appImage_setValid(struct AppImageStore *info, bool valid);

/**
 * \brief Set image address and size
 * \param info Pointer to the image store struct
 * \param type Image storage type
 * \param offset Offset in flash where the image is stored
 * \param size Size of the image
 */
void appImage_setStore(struct AppImageStore *info, enum AppImageStorage type, size_t offset, size_t size);

/**
 * \brief Set currently-running image variant name
 * \param info Pointer to the image information structure
 * \param variant Image variant information.
 */
void bootInfo_setCurrentVariant(struct BootInfo *store, const char *variant);

/**
 * \brief Mark image to be loaded
 * \param info Pointer to the image information structure
 */
void appImage_setLoadRequest(struct AppImageInfo *info);

/**
 * \brief Clear image load request
 * \param info Pointer to the image information structure
 */
void appImage_clearLoadRequest(struct AppImageInfo *info);

/**
 * \brief Check if image has a load request
 * \param info Pointer to the image information structure
 * \return true if image has a load request, false otherwise
 */
bool appImage_hasLoadRequest(struct AppImageInfo *info);

/**
 * \brief Check if image is the one currently loaded
 * \param info Pointer to the image information structure
 * \param bootInfo Pointer to the boot information structure
 * \return true if image is the one currently loaded, false otherwise
 */
bool appImage_isCurrent(struct AppImageInfo *info, struct BootInfo *bootInfo);

/**
 * \brief Check if image signature is valid
 * \param imageInfo Pointer to the image information structure
 * \return 0 if verified, BootError otherwise
 */
int appImage_verifySignature(const struct AppImageInfo *imageInfo);

/**
 * \brief Performs multiple checks to verify that the image is loadable. Includes signature verification.
 * \param imageStore Pointer to the image information structure
 * \param bootInfo Pointer to the boot information structure
 * \return 0 if verified, BootError otherwise
 */
int appImage_verify(const struct AppImageStore *imageStore, const struct BootInfo *bootInfo);

/**
 * \brief Get the signature message data for an image
 * \param imageInfo Pointer to the image information structure
 * \param messageOut Pointer to the output of signature message data.
 * \param messageBuff A buffer where message strings are stored. Must be at least of size BOOT_SIGNATURE_MESSAGE_MAX_SIZE
 * \return 0 if verified, BootError otherwise
 */
int appImage_getSignatureMessage(const struct AppImageInfo *imageInfo, struct SignatureMessage *messageOut, char *messageBuff);

/**
 * \brief Transfer an image from one store to another. If the destination is the app area image will be decrypted, if the source is the app area image will be encrypted.
 * \param fromStore Pointer to the source image store
 * \param toStore Pointer to the destination image store
 * \param bootInfo Optional. Pointer to the boot information structure. if not NULL bootInfo will be saved automatically.
 * \return 0 on success, BootError on error
 */
int appImage_transfer(struct AppImageStore *fromStore, struct AppImageStore *toStore, struct BootInfo *bootInfo);

/**
 * \brief Perfrom checksum on image
 * \param store Pointer to the image store
 * \return 0 if checksum matches signature, BootError on error
 */
int appImage_verifyChecksum(const struct AppImageStore *store);

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