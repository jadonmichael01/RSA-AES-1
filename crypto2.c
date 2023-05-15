#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#define AES_KEY_SIZE 256
#define AES_BLOCK_SIZE 16
#define RSA_KEY_SIZE 2048

void handle_errors() {
    char error_string[256];
    unsigned long error_code = ERR_get_error();
    ERR_error_string_n(error_code, error_string, sizeof(error_string));
    printf("An error occurred: %s\n", error_string);
}

int main() {
    unsigned char key[AES_KEY_SIZE / 8];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char plaintext[] = "Hello, AES and RSA!";
    unsigned char ciphertext[sizeof(plaintext)];
    unsigned char decrypted[sizeof(plaintext)];

    int encrypted_aes_key_len;
    unsigned char encrypted_aes_key[RSA_KEY_SIZE / 8];
    unsigned char decrypted_aes_key[AES_KEY_SIZE / 8];

    EVP_CIPHER_CTX *aes_ctx;
    RSA *rsaKey;
    BIGNUM *e;
    int ret;

    // Generate AES Key and IV
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    // AES Encryption
    aes_ctx = EVP_CIPHER_CTX_new();
    ret = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ret != 1) {
        handle_errors();
        return ret;
    }

    int ciphertext_len;
    ret = EVP_EncryptUpdate(aes_ctx, ciphertext, &ciphertext_len, plaintext, strlen((char *)plaintext) + 1);
    if (ret != 1) {
        handle_errors();
        return ret;
    }

    int final_len;
    ret = EVP_EncryptFinal_ex(aes_ctx, ciphertext + ciphertext_len, &final_len);
    if (ret != 1) {
        handle_errors();
        return ret;
    }
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(aes_ctx);

    // AES Decryption
    aes_ctx = EVP_CIPHER_CTX_new();
    ret = EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    if (ret != 1) {
        handle_errors();
        return ret;
    }

    int decrypted_len;
    ret = EVP_DecryptUpdate(aes_ctx, decrypted, &decrypted_len, ciphertext, ciphertext_len);
    if (ret != 1) {
        handle_errors();
        return ret;
    }

    ret = EVP_DecryptFinal_ex(aes_ctx, decrypted + decrypted_len, &final_len);
    if (ret != 1) {
        handle_errors();
        return ret;
    }
    decrypted_len += final_len;

    EVP_CIPHER_CTX_free(aes_ctx);

    printf("AES Ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    printf("AES Decrypted: %s\n", decrypted);

    // RSA Key Generation
    e = BN_new();
    BN_set_word(e, RSA_F4);
    rsaKey = RSA_new();

    if (!RSA_generate_key_ex(rsaKey, RSA_KEY_SIZE, e, NULL)) {
        handle_errors();
        return -1;
    }

    // RSA Encryption
    encrypted_aes_key_len = RSA_public_encrypt(sizeof(key), key,     encrypted_aes_key, rsaKey, RSA_PKCS1_PADDING);
    if (encrypted_aes_key_len == -1) {
        handle_errors();
        return -1;
    }

    printf("RSA Encrypted AES Key: ");
    for (int i = 0; i < encrypted_aes_key_len; i++) {
        printf("%02x", encrypted_aes_key[i]);
    }
    printf("\n");

    // RSA Decryption
    int decrypted_aes_key_len = RSA_private_decrypt(encrypted_aes_key_len, encrypted_aes_key, decrypted_aes_key, rsaKey, RSA_PKCS1_PADDING);
    if (decrypted_aes_key_len == -1) {
        handle_errors();
        return -1;
    }

    printf("RSA Decrypted AES Key: ");
    for (int i = 0; i < decrypted_aes_key_len; i++) {
        printf("%02x", decrypted_aes_key[i]);
    }
    printf("\n");

    // Cleanup
    BN_free(e);
    RSA_free(rsaKey);

    return 0;
}


