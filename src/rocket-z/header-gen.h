/**
 * @file header-gen.h
 * @brief Functions to generate and edit image headers
 * @details This is normally done on PC side while generating an image, but can be done on device side as well.
 */

#ifndef HEADER_GEN_H
#define HEADER_GEN_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "structs.h"

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

#ifdef __cplusplus
}
#endif

#endif // HEADER_GEN_H