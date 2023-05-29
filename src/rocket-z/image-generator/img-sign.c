#include <stdio.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

void print_usage()
{
    printf("Usage:\n");
    printf("img-sign {-f file_path | -d base64_sha256_string -s file_size} [-a author_id] [-v variant_pattern] [-k key_file]\n");
}

EC_KEY *readPrivateKey(char *key_file)
{
    EC_KEY *key = NULL;
    FILE *fp = fopen(key_file, "r");
    if (fp == NULL)
    {
        printf("Unable to open key file %s\n", key_file);
        return NULL;
    }
    key = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

void Base64Encode(const unsigned char *buffer, size_t length, char *encodedData)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    // remove newlines
    int j = 0;

    for (int i = 0; i < bufferPtr->length; i++)
    {
        if (bufferPtr->data[i] != '\n' && bufferPtr->data[i + 1] != '\r')
        {
            encodedData[j++] = bufferPtr->data[i];
        }

        if (bufferPtr->data[i] == '\0')
            break;
    }

    encodedData[j] = '\0';
}

int main(int argc, char **argv)
{
    int opt;
    char *file_path = NULL;
    char *base64_string = NULL;
    char *file_size = NULL;
    char *key_file = NULL;

    // JSON arguments
    uint32_t version = 0x0;
    char sha256_base64[1024];
    char *authorId;
    uint32_t size;
    char *authenticator = "Zodiac";
    char *variantPattern = NULL;

    while ((opt = getopt(argc, argv, "f:d:s:a:v:k:")) != -1)
    {
        switch (opt)
        {
        case 'f':
            file_path = optarg;
            break;
        case 'd':
            base64_string = optarg;
            break;
        case 's':
            file_size = optarg;
            break;
        case 'a':
            authorId = optarg;
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'v':
            variantPattern = optarg;
            break;
        default:
            print_usage();
            return 1;
        }
    }

    if ((file_path == NULL && (base64_string == NULL || file_size == NULL)) || authorId == NULL || key_file == NULL || variantPattern == NULL)
    {
        print_usage();
        return 1;
    }

    if (NULL != file_path)
    {
        // Open the file
        FILE *file = fopen(file_path, "rb");
        if (!file)
        {
            perror("fopen");
            return 1;
        }

        // Compute the SHA-256 hash
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        const int bufSize = 1048576 * 2; // 1MiB
        char *buffer = malloc(bufSize);
        int bytesRead = 0;
        while ((bytesRead = fread(buffer, 1, bufSize, file)))
        {
            SHA256_Update(&sha256, buffer, bytesRead);
        }
        SHA256_Final(hash, &sha256);

        // Base64 encode the hash
        Base64Encode(hash, SHA256_DIGEST_LENGTH, sha256_base64);

        // get file size
        fseek(file, 0L, SEEK_END);
        size = ftell(file);
    }
    else
    {
        strcpy(sha256_base64, base64_string);
        size = atoi(file_size);
    }

    char msg[2048];
    char msg_base64[1024];

    sprintf(msg, "{\"authenticator\":\"%s\",\"time\":%lu,\"authorId\":\"%s\",\"variantPattern\":\"%s\",\"sha256\":\"%s\",\"size\":%d}", authenticator, time(NULL), authorId, variantPattern, sha256_base64, size);

    // Base64 encode the message
    Base64Encode(msg, strlen(msg), msg_base64);

    // get signature

    EC_KEY *eckey = NULL;
    const EC_GROUP *group;
    unsigned char digest[32];
    unsigned char *signature = NULL;
    char base64Signature[1024];
    unsigned int sig_len;

    eckey = readPrivateKey(key_file);
    if (eckey == NULL)
        return 1;

    // Create a SHA-256 hash of the message
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msg, strlen(msg));
    SHA256_Final(digest, &sha256);

    sig_len = ECDSA_size(eckey);
    signature = malloc(sig_len);

    if (!ECDSA_sign(0, digest, sizeof(digest), signature, &sig_len, eckey))
    {
        free(signature);
        return 1;
    }

    // Base64 encode the signature
    Base64Encode(signature, sig_len, base64Signature);

    printf("%d\n%s\n%s\n", version, msg_base64, base64Signature);

    return 0;
}

void bootLog(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    printf("\n");
}