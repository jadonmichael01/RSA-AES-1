#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>


#define AES_KEY_SIZE 256

void handleErrors()
{
    unsigned long error_code = ERR_get_error();
    char error_string[256];
    ERR_error_string_n(error_code, error_string, sizeof(error_string));
    fprintf(stderr, "An error occurred: %s\n", error_string);
    exit(1);
}


void encryptAES(const unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    AES_KEY aesKey;
    AES_set_encrypt_key(key, AES_KEY_SIZE, &aesKey);
    AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &aesKey, iv, AES_ENCRYPT);
}

void decryptAES(const unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    AES_KEY aesKey;
    AES_set_decrypt_key(key, AES_KEY_SIZE, &aesKey);
    AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &aesKey, iv, AES_DECRYPT);
}


RSA *generateRSAKey()
{
    RSA *rsaKey = NULL;
    BIGNUM *e = NULL;
    int bits = 2048;
    unsigned long e_value = RSA_F4;

    e = BN_new();
    if (!e)
        handleErrors();

    if (!BN_set_word(e, e_value))
        handleErrors();

    rsaKey = RSA_new_method(NULL);
    if (!rsaKey)
        handleErrors();

    if (!RSA_generate_key_ex(rsaKey, bits, e, NULL))
        handleErrors();

    BN_free(e);
    return rsaKey;
}

void encryptRSA(RSA *rsaKey, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext)
{
    int encrypted_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsaKey, RSA_PKCS1_PADDING);
    if (encrypted_len == -1)
        handleErrors();
}

void decryptRSA(RSA *rsaKey, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext)
{
    int decrypted_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsaKey, RSA_PKCS1_PADDING);
    if (decrypted_len == -1)
        handleErrors();
}

int main()
{
    const char *message = "Hello, AES and RSA!";
    const int message_len = strlen(message) + 1;

    unsigned char aes_key[AES_KEY_SIZE / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char aes_ciphertext[message_len];
    unsigned char aes_decrypted[message_len];

    // Generate AES key and IV
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        handleErrors();
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1)
        handleErrors();

    // Create a copy of the original IV
    unsigned char original_iv[AES_BLOCK_SIZE];
    memcpy(original_iv, iv, sizeof(iv));

    // Encrypt using AES
    encryptAES((const unsigned char *)message, message_len, aes_key, iv, aes_ciphertext);

    // Print AES ciphertext
    printf("AES Ciphertext: ");
    for (int i = 0; i < message_len; i++)
        printf("%02x", aes_ciphertext[i]);
    printf("\n");

    // Decrypt AES ciphertext using the original IV
    decryptAES(aes_ciphertext, message_len, aes_key, original_iv, aes_decrypted);
    printf("AES Decrypted: %s\n", aes_decrypted);

    // Generate RSA key pair
    RSA *rsaKey = generateRSAKey();

    // Encrypt AES key using RSA
    unsigned char rsa_encrypted[AES_KEY_SIZE / 8];
        encryptRSA(rsaKey, aes_key, AES_KEY_SIZE / 8, rsa_encrypted);

    // Print RSA encrypted AES key
    printf("RSA Encrypted AES Key: ");
    for (int i = 0; i < AES_KEY_SIZE / 8; i++)
        printf("%02x", rsa_encrypted[i]);
    printf("\n");

    // Decrypt RSA encrypted AES key
    unsigned char rsa_decrypted[AES_KEY_SIZE / 8];
    decryptRSA(rsaKey, rsa_encrypted, AES_KEY_SIZE / 8, rsa_decrypted);

    // Compare decrypted AES key with original AES key
    if (memcmp(aes_key, rsa_decrypted, AES_KEY_SIZE / 8) == 0)
        printf("RSA Decryption Successful.\n");
    else
        printf("RSA Decryption Failed.\n");

    // Clean up
    RSA_free(rsaKey);

    return 0;
}

