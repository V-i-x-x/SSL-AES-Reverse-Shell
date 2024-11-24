#include "AES_CBC.h"
#include <sstream>
#include <vector>

AES_CBC::AES_CBC(const unsigned char* key, const unsigned char* fixed_iv) {
    std::memcpy(iv, fixed_iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &encryptKey);
    AES_set_decrypt_key(key, 128, &decryptKey);
}

void AES_CBC::encrypt(unsigned char* input, unsigned char* output, int length) {
    unsigned char iv_copy[AES_BLOCK_SIZE];
    std::memcpy(iv_copy, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(input, output, length, &encryptKey, iv_copy, AES_ENCRYPT);
}

void AES_CBC::decrypt(unsigned char* input, unsigned char* output, int length) {
    unsigned char iv_copy[AES_BLOCK_SIZE];
    std::memcpy(iv_copy, iv, AES_BLOCK_SIZE);
    AES_cbc_encrypt(input, output, length, &decryptKey, iv_copy, AES_DECRYPT);
}

void AES_CBC::printHex(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    std::cout << std::endl;
}

// Function to convert binary data to a hex string
std::string toHex(const unsigned char* data, size_t length) {
    std::ostringstream hexStream;
    for (size_t i = 0; i < length; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return hexStream.str();
}

std::vector<unsigned char> fromHex(const std::string& hex) {
    std::vector<unsigned char> binary;
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = std::stoi(hex.substr(i, 2), nullptr, 16);
        binary.push_back(byte);
    }
    return binary;
}

std::vector<unsigned char> removePadding(const std::vector<unsigned char>& data) {
    size_t paddingLength = data.back();
    if (paddingLength > AES_BLOCK_SIZE || paddingLength > data.size()) {
        throw std::runtime_error("Invalid padding length");
    }
    return std::vector<unsigned char>(data.begin(), data.end() - paddingLength);
}

std::string decryptCommand(const std::string& encryptedHex, AES_CBC& aes) {
    // Convert hex string to binary
    std::vector<unsigned char> encryptedBinary = fromHex(encryptedHex);

    // Decrypt the binary data
    std::vector<unsigned char> decryptedBinary(encryptedBinary.size());
    aes.decrypt(encryptedBinary.data(), decryptedBinary.data(), encryptedBinary.size());

    // Remove padding
    std::vector<unsigned char> unpaddedData = removePadding(decryptedBinary);

    // Convert to string
    return std::string(unpaddedData.begin(), unpaddedData.end());
}

std::string encryptCommand(const std::string& command, AES_CBC& aes) {
    // Convert the command string to binary (vector of unsigned char)
    std::vector<unsigned char> commandBinary(command.begin(), command.end());

    // Padding the data to ensure it is a multiple of AES_BLOCK_SIZE
    int paddedLength = (commandBinary.size() / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
    std::vector<unsigned char> paddedData(paddedLength);
    std::memcpy(paddedData.data(), commandBinary.data(), commandBinary.size());
    std::memset(paddedData.data() + commandBinary.size(), 0, paddedLength - commandBinary.size());

    // Encrypt the data
    std::vector<unsigned char> encryptedData(paddedLength);
    aes.encrypt(paddedData.data(), encryptedData.data(), paddedLength);

    // Convert the encrypted binary data to a hex string
    return toHex(encryptedData.data(), encryptedData.size());
}
