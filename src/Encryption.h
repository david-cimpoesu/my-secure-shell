#ifndef SERVER_ENCRYPTION_H
#define SERVER_ENCRYPTION_H

#include <map>
#include <openssl/evp.h>

// Maximum buffer size used for message encryption/decryption
#define MAX_BUFFER_SIZE 1024

// Prints the most recent OpenSSL error and terminates the program.
void handle_openssl_error();

// Encrypts a message using AES-128-ECB and sends it to the client.
void send_encrypted_message(int sockfd, const unsigned char* message, int message_len, const unsigned char* key);

// Receives and decrypts a message from the client using AES-128-ECB.
int receive_encrypted_message(int sockfd, unsigned char* buffer, int buffer_size, const unsigned char* key);

#endif // SERVER_ENCRYPTION_H

