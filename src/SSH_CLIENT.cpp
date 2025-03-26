/*======================================================================================PROJECT: MY SSH - CLIENT SIDE ============================================================================*/

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sqlite3.h>
#include <bcrypt.h>

#include "Encryption.h"
#include "Globals.h"

#define PORT 2727
#define SERVER_ADDR "127.0.0.1"
#define MAX_BUFFER_SIZE 1024

using namespace std;
const string CYAN_BOLD = "\x1b[36;1m";
const string RESET = "\x1b[0m";

// Performs RSA key exchange to securely obtain an AES session key from the server.
void client_negotiate_key(int sockfd, unsigned char* key) {
    cout << "Client: Starting key negotiation..." << endl;

    RSA* rsa_keypair = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa_keypair, 2048, e, NULL)) {
        cerr << "Client: Error generating RSA key pair." << endl;
        BN_free(e);
        RSA_free(rsa_keypair);
        exit(1);
    }
    BN_free(e);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, rsa_keypair);

    size_t pubkey_len = BIO_pending(bio);
    unsigned char* pubkey = (unsigned char*)malloc(pubkey_len);
    BIO_read(bio, pubkey, pubkey_len);
    BIO_free(bio);

    send(sockfd, pubkey, pubkey_len, 0);
    cout << "Client: Sent public key to server. Length: " << pubkey_len << endl;
    free(pubkey);

    unsigned char encrypted_key[256];
    int encrypted_key_len = recv(sockfd, encrypted_key, sizeof(encrypted_key), 0);
    if (encrypted_key_len <= 0) {
        cerr << "Client: Error receiving encrypted AES key from server." << endl;
        RSA_free(rsa_keypair);
        exit(1);
    }

    cout << "Client: Received encrypted AES key. Length: " << encrypted_key_len << endl;

    int decrypted_key_len = RSA_private_decrypt(encrypted_key_len, encrypted_key, key, rsa_keypair, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa_keypair);

    if (decrypted_key_len != 16) {
        cerr << "Client: Error decrypting AES key. Decrypted length: " << decrypted_key_len << endl;
        exit(1);
    }

    cout << "Client: Decrypted AES key: ";
    for (int i = 0; i < 16; i++) {
        printf("%02x", key[i]);
    }
    cout << endl;
}


int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Socket error");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);

    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect error");
        return 1;
    }

    cout << "Client: Connected to server." << endl;

    unsigned char aes_key[16];
    client_negotiate_key(sockfd, aes_key);
    
    // Entry point of the SSH client: connects to the server over TCP and starts AES key negotiation.
    // Sends encrypted commands and receives encrypted responses in a loop until "quit".

    while (true) {
        
        string command;
        cout << CYAN_BOLD << "My Secure Shell: " <<RESET;
        getline(cin, command);

        send_encrypted_message(sockfd, (unsigned char*)command.c_str(), command.size(), aes_key);

        if (command == "quit") break;

        unsigned char buffer[MAX_BUFFER_SIZE];
        int len = receive_encrypted_message(sockfd, buffer, MAX_BUFFER_SIZE, aes_key);
        if (len <= 0) {
            cerr << "Error: Could not receive a valid response from the server." << endl;
            break;
        }

        cout << "Server response: " << buffer << endl;
    }

    close(sockfd);
    return 0;
}
