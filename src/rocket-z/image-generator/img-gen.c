/**
 * \file image-gen.c
 * \brief Generate image files. Can be compiled on OS systems.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/obj_mac.h> //For NID_secp256k1
#include "../controller.h"

void print_help()
{
    fprintf(stderr, "Usage: img-gen -f binary_file -n image_name -s signature_file -k bootloader_public_pem_file [-c bootloader_key_crc32] -o output_file [-u unencrypted_image_output]\n\n");
    fprintf(stderr, "This tool performs cryptographic operations on the input binary file using the provided signature and PEM file.\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help    Show this help message and exit.\n");
}

#define MAX_LENGTH 1024

int decode(const char *input, unsigned char *output, size_t *out_len)
{
    BIO *b64, *bio;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    *out_len = BIO_read(bio, output, strlen(input));

    output[*out_len] = '\0';

    BIO_free_all(bio);

    return *out_len;
}

// for pemDecode.c
int pem_base64_decode(uint8_t *dst, size_t dlen, size_t *olen, const uint8_t *src, size_t slen)
{
    return decode(src, dst, olen);
}

void bootLog(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

void handleErrors(void)
{
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void strip_pem_header_footer(char *pem_str)
{
    const char *header = "-----BEGIN PUBLIC KEY-----\n";
    const char *footer = "\n-----END PUBLIC KEY-----";
    char *start, *end;

    if ((start = strstr(pem_str, header)))
    {
        start += strlen(header);
    }
    else
    {
        fprintf(stderr, "PEM string does not contain a valid header\n");
        return;
    }

    if ((end = strstr(pem_str, footer)))
    {
        *end = '\0';
    }
    else
    {
        fprintf(stderr, "PEM string does not contain a valid footer\n");
        return;
    }

    memmove(pem_str, start, end - start + 1);
}

#ifdef _WIN32
ssize_t getline(char **lineptr, size_t *n, FILE *stream)
{
    char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (lineptr == NULL)
    {
        return -1;
    }
    if (stream == NULL)
    {
        return -1;
    }
    if (n == NULL)
    {
        return -1;
    }
    bufptr = *lineptr;
    size = *n;

    c = fgetc(stream);
    if (c == EOF)
    {
        return -1;
    }
    if (bufptr == NULL)
    {
        bufptr = malloc(128);
        if (bufptr == NULL)
        {
            return -1;
        }
        size = 128;
    }
    p = bufptr;
    while (c != EOF)
    {
        if ((p - bufptr) > (size - 1))
        {
            size = size + 128;
            bufptr = realloc(bufptr, size);
            if (bufptr == NULL)
            {
                return -1;
            }
        }
        *p++ = c;
        if (c == '\n')
        {
            break;
        }
        c = fgetc(stream);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
}
#endif

int main(int argc, char *argv[])
{
    if (argc < 5)
    {
        print_help();
        return 1;
    }

    char *file_path = NULL;
    char *imageName = NULL;
    char *signatureFile = NULL;
    char *publicKeyFile = NULL;
    char *outputFile = NULL;
    char *unencryptedFileOutput = NULL;
    uint32_t crc32 = 0;

    int opt;

    while ((opt = getopt(argc, argv, "n:k:s:f:o:c:u:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            file_path = optarg;
            break;
        case 'n':
            imageName = optarg;
            break;
        case 's':
            signatureFile = optarg;
            break;
        case 'k':
            publicKeyFile = optarg;
            break;
        case 'o':
            outputFile = optarg;
            break;
        case 'u':
            unencryptedFileOutput = optarg;
            break;
        case 'c':
            crc32 = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Invalid option. %s\n", optarg);
            print_help();
            return 1;
        }
    }

    FILE *signature = fopen(signatureFile, "rb");

    if (signature == NULL)
    {
        fprintf(stderr, "Failed to open signature file.\n");
        return 1;
    }

    // read each line in signature file and decode it
    char *line;
    ssize_t read;
    char signature_message[MAX_LENGTH];
    size_t signature_decoded_len = 0;

    size_t len = 0;

    read = getline((char **)&line, &len, signature);

    int version = atoi(line);

    memset(signature_message, 0, MAX_LENGTH);

    read = getline(&line, &len, signature);

    decode(line, signature_message, &signature_decoded_len);

    char signature_pem[MAX_LENGTH];
    memset(signature_pem, 0, MAX_LENGTH);

    read = getline(&line, &len, signature);

    strcpy(signature_pem, line);

    // Do the crypto !!

    EC_KEY *key, *peer_key;
    EVP_PKEY *pkey, *peer_pkey;
    EVP_PKEY_CTX *ctx;
    size_t secret_len;
    unsigned char *secret;

    // Step 1: Generate EC params for EC p256
    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
    {
        fprintf(stderr, "Failed to create EC key\n");
        return 1;
    }

    // Step 2: Generate EC key pair
    if (EC_KEY_generate_key(key) != 1)
    {
        fprintf(stderr, "Failed to generate EC key\n");
        return 1;
    }

    // Convert to PEM format
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_EC_PUBKEY(bio, key);
    char *public_key;

    long public_key_len = BIO_get_mem_data(bio, &public_key);

    // read peer public key from file into a string
    FILE *public_key_file = fopen(publicKeyFile, "rb");

    if (public_key_file == NULL)
    {
        fprintf(stderr, "Failed to open public key file.\n");
        return 1;
    }

    char peerPublicKey[MAX_LENGTH];

    memset(peerPublicKey, 0, MAX_LENGTH);

    read = fread(peerPublicKey, 1, MAX_LENGTH, public_key_file);

    if (read < 0)
    {
        fprintf(stderr, "Could not read file\n");
        return 1;
    }

    // Existing public key
    char *peer_public_key_string = peerPublicKey;
    BIO *bio2 = BIO_new_mem_buf(peer_public_key_string, -1);
    peer_key = PEM_read_bio_EC_PUBKEY(bio2, NULL, NULL, NULL);

    // Create the context for the shared secret derivation
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(pkey, key);
    peer_pkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(peer_pkey, peer_key);
    ctx = EVP_PKEY_CTX_new(pkey, NULL);

    // Initialise the context and shared secret derivation
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        fprintf(stderr, "Failed to initialise ctx\n");
        return 1;
    }

    // Provide the peer public key
    if (EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0)
    {
        fprintf(stderr, "Failed to set peer key\n");
        return 1;
    }

    // Determine buffer length for shared secret
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0)
    {
        fprintf(stderr, "Failed to determine buffer length\n");
        return 1;
    }

    // Create the buffer
    secret = OPENSSL_malloc(secret_len);

    // Derive the shared secret
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0)
    {
        fprintf(stderr, "Failed to derive shared secret\n");
        return 1;
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, secret, secret_len);
    SHA256_Final(hash, &sha256);

    unsigned char *aesKey = hash;
    unsigned char *iv = hash + 16;

    // Load the necessary cipher
    EVP_add_cipher(EVP_aes_128_cbc());

    // Read the file into a buffer
    FILE *file = fopen(file_path, "rb");
    if (!file)
    {
        fprintf(stderr, "Could not open file\n");
        return 1;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Read the file into a buffer
    unsigned char *plaintext = malloc(fsize + 1);
    read = fread(plaintext, 1, fsize, file);

    if (read < 0)
    {
        fprintf(stderr, "Could not read file\n");
        return 1;
    }

    fclose(file);

    // Allocate memory for the ciphertext
    unsigned char ciphertext[fsize + EVP_MAX_BLOCK_LENGTH];

    // Perform the encryption
    int ciphertext_len = encrypt(plaintext, fsize, aesKey, iv, ciphertext);

    struct AppImageHeader header;

    appImage_setHeader(&header, IMAGE_HEADER_VERSION_0_0, 0x400);

    appImage_setName(&header, imageName);

    appImage_setEncryption(&header, public_key, ENCRYPTION_EC_P256_AES_128_CBC_SHA_256, ciphertext_len, crc32);

    appImage_setSignature(&header, signature_message, signature_pem, SIGNATURE_VERSION_0_0);

    FILE *output = fopen(outputFile, "wb");

    if (output == NULL)
    {
        fprintf(stderr, "Failed to open output file.\n");
        return 1;
    }

    int size = fwrite(&header, sizeof(header), 1, output);

    if (size != 1)
    {
        fprintf(stderr, "Failed to write header to output file. %i.\n", size);
        return 1;
    }

    size = fwrite(ciphertext, 0x400 - sizeof(header), 1, output);

    if (size != 1)
    {
        fprintf(stderr, "Failed to write header data to output file.\n");
        return 1;
    }

    // write ciphertext
    size = fwrite(ciphertext, ciphertext_len, 1, output);

    if (size != 1)
    {
        fprintf(stderr, "Failed to write ciphertext to output file.\n");
        return 1;
    }

    if (NULL != unencryptedFileOutput)
    {

        appImage_setEncryption(&header, public_key, ENCRYPTION_NONE, fsize, crc32);

        FILE *output = fopen(unencryptedFileOutput, "wb");

        if (output == NULL)
        {
            fprintf(stderr, "Failed to open output file.\n");
            return 1;
        }

        int size = fwrite(&header, sizeof(header), 1, output);

        if (size != 1)
        {
            fprintf(stderr, "Failed to write header to output file. %i.\n", size);
            return 1;
        }

        size = fwrite(plaintext, 0x400 - sizeof(header), 1, output);

        if (size != 1)
        {
            fprintf(stderr, "Failed to write header data to output file.\n");
            return 1;
        }

        // write ciphertext
        size = fwrite(plaintext, fsize, 1, output);

        if (size != 1)
        {
            fprintf(stderr, "Failed to write ciphertext to output file.\n");
            return 1;
        }
    }

    // Cleanup
    free(plaintext);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_pkey);
    EVP_PKEY_free(pkey);
    EC_KEY_free(peer_key);
    EC_KEY_free(key);
    BIO_free(bio);
    BIO_free(bio2);
    OPENSSL_free(secret);

    return 0;
}
