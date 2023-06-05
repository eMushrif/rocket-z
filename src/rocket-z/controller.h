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

#include "structs.h"
#include "boot-info-ctrl.h"

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
     * \brief Get the signature message data for an image
     * \param header Pointer to the image header structure
     * \param messageOut Pointer to the output of signature message data.
     * \param messageBuff A buffer where message strings are stored. Must be at least of size CONFIG_ROCKETZ_SIGNATURE_MESSAGE_MAX_SIZE
     * \return 0 on success, BootError otherwise
     */
    enum BootError appImage_getSignatureMessage(const struct AppImageHeader *header, struct AppImageSignatureMessage *messageOut, char *messageBuff);

#ifdef __cplusplus
}
#endif

#endif /* CONTROLLER_H_ */