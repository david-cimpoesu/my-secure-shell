#include <iostream>
#include <cstring>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#include "Globals.h"
#include "Encryption.h"

// Prints the most recent OpenSSL error and terminates the program.
void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

// Encrypts a message using AES-128-ECB and sends it to the client.
void send_encrypted_message(int sockfd, const unsigned char* message, int message_len, const unsigned char* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) handle_openssl_error();

    unsigned char ciphertext[MAX_BUFFER_SIZE];
    int len, textcifru_len = 0;

    cout << "[DEBUG] Message before encryption: " << string((char*)message, message_len) << endl;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, message, message_len) != 1) handle_openssl_error();
    textcifru_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) handle_openssl_error();
    textcifru_len += len;

    cout << "[DEBUG] Encrypted message (hex): ";
    for (int i = 0; i < textcifru_len; i++) printf("%02x", ciphertext[i]);
    cout << endl;

    send(sockfd, &textcifru_len, sizeof(textcifru_len), 0);
    send(sockfd, ciphertext, textcifru_len, 0);
    EVP_CIPHER_CTX_free(ctx);
}

// Receives and decrypts a message from the client using AES-128-ECB.
int receive_encrypted_message(int sockfd, unsigned char* buffer, int buffer_size, const unsigned char* key) {
    unsigned char textcifru[MAX_BUFFER_SIZE];
    int textcifru_lungime = 0;
    int len, textsimplu_len = 0;

    if (recv(sockfd, &textcifru_lungime, sizeof(textcifru_lungime), 0) <= 0) return -1;
    if (recv(sockfd, textcifru, textcifru_lungime, 0) <= 0) return -1;

    // Debug: Mesajul criptat primit (în format hexazecimal)
     cout << "[DEBUG] Encrypted message received (hex): ";
    for (int i = 0; i < textcifru_lungime; i++) printf("%02x", textcifru[i]);
    cout << endl; 

    // contextul de decriptare
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_openssl_error();

    // Inițializăm contextul cu AES-128-ECB și cheia AES
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1) handle_openssl_error();

    // Decriptăm mesajul
    if (EVP_DecryptUpdate(ctx, buffer, &len, textcifru, textcifru_lungime) != 1) handle_openssl_error();
    textsimplu_len += len;
    if (EVP_DecryptFinal_ex(ctx, buffer + len, &len) != 1) handle_openssl_error();
    textsimplu_len += len;

    // Debug: Mesajul decriptat după primire
     cout << "[DEBUG] Decrypted message: " << string((char*)buffer, textsimplu_len) << endl;

    EVP_CIPHER_CTX_free(ctx);
    buffer[textsimplu_len] = '\0';

    return textsimplu_len;
}

// Generates a random AES session key and sends it securely to the client using RSA public key encryption.
void negotiate_key(int client_socket, map<int, unsigned char[16]>& client_aes_keys) {
    unsigned char key[16];
    cout << "Server: Starting key negotiation..." << endl;

    bool is_key_generated = RAND_bytes(key, 16);
    if (!is_key_generated) {
        cerr << "Server: Failed to generate AES key." << endl;
        return;
    }

    // Stochează cheia pentru clientul curent
    memcpy(client_aes_keys[client_socket], key, 16);

    cout << "Server: Successfully negotiated AES key: ";
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
        if (i == 15) cout << endl;
    }

    unsigned char client_pubkey[2048] = {0};
    int pubkey_len = recv(client_socket, client_pubkey, sizeof(client_pubkey), 0);
    bool is_pubkey_valid = (pubkey_len > 0);
    if (!is_pubkey_valid) {
        cerr << "Server: Error receiving public key from client." << endl;
        return;
    }

    BIO* bio = BIO_new_mem_buf(client_pubkey, pubkey_len);
    RSA* rsa_pubkey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!rsa_pubkey) {
        cerr << "Server: Error parsing client's public key." << endl;
        return;
    }

    unsigned char encrypted_key[256];
    int encrypted_key_len;
    encrypted_key_len = RSA_public_encrypt(16, key, encrypted_key, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_pubkey);

    if (encrypted_key_len <= 0) {
        cerr << "Server: Error encrypting AES key." << endl;
        return;
    }

    send(client_socket, encrypted_key, encrypted_key_len, 0);
    cout << "Server: Sent encrypted AES key to client." << endl;
}
