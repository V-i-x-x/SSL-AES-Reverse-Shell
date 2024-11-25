#include "AES_CBC.h"
#include <sstream>
#include <vector>

// Constructor: Initializes the AES CBC object with a key and IV.
// Sets up encryption and decryption keys.
AES_CBC::AES_CBC(const unsigned char* key, const unsigned char* fixed_iv) {
    std::memcpy(iv, fixed_iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &encryptKey);
    AES_set_decrypt_key(key, 128, &decryptKey);
}

// Encrypt data using AES in CBC mode.
// The input is plaintext, and the output is ciphertext of the specified length.
void AES_CBC::encrypt(unsigned char* input, unsigned char* output, int length) {
    unsigned char iv_copy[AES_BLOCK_SIZE];
    std::memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy the IV to prevent modification
    AES_cbc_encrypt(input, output, length, &encryptKey, iv_copy, AES_ENCRYPT);
}

// Decrypt data using AES in CBC mode.
// The input is ciphertext, and the output is the decrypted plaintext.
void AES_CBC::decrypt(unsigned char* input, unsigned char* output, int length) {
    unsigned char iv_copy[AES_BLOCK_SIZE];
    std::memcpy(iv_copy, iv, AES_BLOCK_SIZE); // Copy the IV to prevent modification
    AES_cbc_encrypt(input, output, length, &decryptKey, iv_copy, AES_DECRYPT);
}

// Print binary data in hexadecimal format for easier readability.
void AES_CBC::printHex(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::endl;
}

// Convert binary data to a hexadecimal string representation.
std::string toHex(const unsigned char* data, size_t length) {
    std::ostringstream hexStream;
    for (size_t i = 0; i < length; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return hexStream.str();
}

// Convert a hexadecimal string to binary data.
std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> binary;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        binary.push_back(byte);
    }
    return binary;
}

// Remove PKCS7 padding from decrypted data.
// Validates padding before removing it.
std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data) {
    size_t paddingLength = data.back(); // Last byte indicates padding length
    if (paddingLength > AES_BLOCK_SIZE || paddingLength > data.size()) {
        throw std::runtime_error("Invalid padding length");
    }
    return std::vector<unsigned char>(data.begin(), data.end() - paddingLength);
}

// Decrypt a command represented as a hexadecimal string.
// Converts hex to binary, decrypts the data, removes padding, and returns plaintext.
std::string decryptCommand(const std::string& encryptedHex, AES_CBC& aes) {
    std::vector<unsigned char> encryptedBinary = fromHex(encryptedHex); // Convert hex to binary
    std::vector<unsigned char> decryptedBinary(encryptedBinary.size());
    aes.decrypt(encryptedBinary.data(), decryptedBinary.data(), encryptedBinary.size()); // Decrypt

    std::vector<unsigned char> unpaddedData = removePadding(decryptedBinary); // Remove padding
    return std::string(unpaddedData.begin(), unpaddedData.end()); // Convert to string
}

// Encrypt a command string using AES in CBC mode.
// Pads the command, encrypts it, and returns the result as a hex string.
std::string encryptCommand(const std::string& command, AES_CBC& aes) {
    std::vector<unsigned char> commandBinary(command.begin(), command.end()); // Convert string to binary

    int paddedLength = (commandBinary.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE; // Calculate padded length
    std::vector<unsigned char> paddedData(paddedLength);
    std::memcpy(paddedData.data(), commandBinary.data(), commandBinary.size()); // Copy original data
    std::memset(paddedData.data() + commandBinary.size(), 0, paddedLength - commandBinary.size()); // Add padding

    std::vector<unsigned char> encryptedData(paddedLength);
    aes.encrypt(paddedData.data(), encryptedData.data(), paddedLength); // Encrypt the padded data

    return toHex(encryptedData.data(), encryptedData.size()); // Convert to hex and return
}
