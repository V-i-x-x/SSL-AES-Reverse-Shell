#ifndef AES_CBC_H
#define AES_CBC_H

#include <openssl/aes.h>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>
#pragma warning(disable : 4996)

class AES_CBC {
public:
    // Constructor to initialize the AES_CBC object with the encryption key and fixed IV
    AES_CBC(const unsigned char* key, const unsigned char* fixed_iv);

    // Encrypt data using AES-CBC
    void encrypt(unsigned char* input, unsigned char* output, int length);

    // Decrypt data using AES-CBC
    void decrypt(unsigned char* input, unsigned char* output, int length);

    // Print data in hex format for debugging
    void printHex(unsigned char* data, int length);

private:
    AES_KEY encryptKey;    // AES encryption key
    AES_KEY decryptKey;    // AES decryption key
    unsigned char iv[AES_BLOCK_SIZE];  // Initialization vector for AES-CBC
};

// Function to convert binary data to a hex string
std::string toHex(const unsigned char* data, size_t length);

// Function to convert a hex string to binary data
std::vector<unsigned char> fromHex(const std::string& hex);

// Function to remove padding from decrypted data
std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data);

// Function to decrypt a command from hex format
std::string decryptCommand(const std::string& encryptedHex, AES_CBC& aes);

// Function to encrypt a command into hex format
std::string encryptCommand(const std::string& command, AES_CBC& aes);

#endif // AES_CBC_H