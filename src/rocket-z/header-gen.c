
#include <string.h>
#include "pem/pem-decode.h"
#include "header-gen.h"
#include "boot-log.h"

enum BootError appImage_setName(struct AppImageHeader *header, const char *name)
{
    if (strlen(name) <= sizeof(header->imageName) - 1)
        strcpy(header->imageName, name);
    else
        return BOOT_ERROR_TOO_LARGE;

    return BOOT_ERROR_SUCCESS;
}

void appImage_setHeader(struct AppImageHeader *header, enum AppImageHeaderVersion version, size_t size)
{
    header->headerVersion = version;
    header->headerSize = size;
}

enum BootError appImage_setSignature(struct AppImageHeader *header, const char *message, const char *signature, enum BootSignatureVersion version)
{
    header->signatureInfo.signatureVersion = version;

    if (strlen(message) <= sizeof(header->signatureInfo.message) - 1)
        strcpy(header->signatureInfo.message, message);
    else
        return BOOT_ERROR_TOO_LARGE;

    size_t len = 0;
    int res = pemExtract(signature, EC_P256_SIGNATURE, header->signatureInfo.signature, &len);

    if (0 == len)
    {
        bootLog("ERROR: Setting signature for %.64s. Failed to parse argument. Expecting PEM-formatted prime2561v1 signature. Error %i.", header->imageName, res);
        return BOOT_ERROR_FAILED_PARSE;
    }

    if (res < 0)
    {
        bootLog("WARNING: Setting signature for %.64s. Expecting PEM-formatted prime2561v1 signature. Not sure what the given signature is but I'll try it.\n", header->imageName);
    }

    return BOOT_ERROR_SUCCESS;
}

enum BootError appImage_setEncryption(struct AppImageHeader *header, const char *pubKey, enum AppImageEncryptionMethod method, size_t encryptedSize, uint32_t pubKeyCrc32)
{
    size_t len = 0;
    int res = pemExtract(pubKey, EC_P256_PUBLIC_KEY, header->encryption.pubKey, &len);

    if (0 == len)
    {
        bootLog("ERROR: Setting encryption key for %.64s. Failed to parse argument. Expecting PEM-formatted prime2561v1 public key. Error %i.", header->imageName, res);
        return BOOT_ERROR_FAILED_PARSE;
    }

    if (res < 0)
    {
        bootLog("WARNING: Setting encryption key for %.64s. Expecting PEM-formatted prime2561v1 public key. Not sure what the given key is but I'll try it.\n", header->imageName);
    }

    header->encryption.method = method;
    header->encryption.encryptedSize = encryptedSize;
    header->encryption.pubKeyCrc32 = pubKeyCrc32;

    return BOOT_ERROR_SUCCESS;
}