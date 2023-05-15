# RSA-AES-1

## Overview

RSA-AES-1 is a simple command-line program that demonstrates how to perform hybrid encryption using RSA and AES algorithms. The program generates a random AES key, encrypts a sample plaintext with the key, and then decrypts the ciphertext back to the original plaintext. The AES key is also encrypted and decrypted using RSA public key cryptography.

The crypto1.c file is a legacy testing file that utilizes deprecated methods and relies on outdated dependencies from the OpenSSL library.


## Usage

1. Compile the program with the following command:

```
gcc crypto2.c -o crypto2 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lcrypto
```

2. Run the program:

```
./crypto2
```

## Output

The program will output the following:

- AES Ciphertext: The encrypted data after AES encryption.
- AES Decrypted: The decrypted data after AES decryption, which should match the original plaintext.
- RSA Encrypted AES Key: The encrypted AES key after RSA encryption.
- RSA Decrypted AES Key: The decrypted AES key after RSA decryption, which should match the original AES key.

## Dependencies

- OpenSSL (with support for EVP functions and RSA key generation)

Please ensure that the OpenSSL library is installed on your system and the appropriate include and library paths are set when compiling the program.
