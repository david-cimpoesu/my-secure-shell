/*======================================================================================PROJECT: MY SSH - SERVER SIDE ============================================================================*/

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <map>
#include <set>

#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "Globals.h"
#include "Encryption.h"         
#include "LoginLogic.h"
#include "AdminRestricted.h"
#include "CommandHandling.h"

using namespace std;
using namespace std;

// Generates a random AES session key and sends it securely to the client using RSA public key encryption.
void server_negotiate_key(int client_socket, map<int, unsigned char[16]>& client_aes_keys) {
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


// Entry point of the concurrent TCP SSH server.
// Uses `select()` for handling multiple encrypted client sessions via AES/RSA key exchange.
int main() {

    //int server_socket;
    struct sockaddr_in server_addr;
    fd_set active_fds, read_fds;
    //int max_fd;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket error");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind error");
        close(server_socket);
        return 1;
    }

    if (listen(server_socket, MAX_CLIENTS) < 0) {
        perror("Listen error");
        close(server_socket);
        return 1;
    }

    FD_ZERO(&active_fds);
    FD_SET(server_socket, &active_fds);
    max_fd = server_socket;

    cout << "Server: Listening on port " << PORT << endl;

    map<int, unsigned char[16]> client_aes_keys;

    while (true) {
        read_fds = active_fds;

        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            perror("Select error");
            break;
        }

        for (int i = 0; i <= max_fd; ++i) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == server_socket) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

                    if (client_socket >= 0) {
                        FD_SET(client_socket, &active_fds);
                        if (client_socket > max_fd) max_fd = client_socket;
                        cout << "Server: Client connected." << endl;
                       server_negotiate_key(client_socket, client_aes_keys);

                    } else {
                        perror("Accept error");
                    }
                } else {
                    unsigned char buffer[MAX_BUFFER_SIZE] = {0};
                    int len = receive_encrypted_message(i, buffer, MAX_BUFFER_SIZE, client_aes_keys[i]);

                    if (len <= 0) {
                        cout << "Server: Client disconnected." << endl;
                       close(i);
                        FD_CLR(i, &active_fds);
                        client_sessions.erase(i);
                        client_aes_keys.erase(i);

                    } else {
                        cout << "Server: Command received: " << buffer << endl;
                       auto key_it = client_aes_keys.find(i);
                        if (key_it != client_aes_keys.end()) {
                            process_command(i, string((char*)buffer), active_fds, key_it->second);
                        } else {
                            cerr << "Error: AES key not found for client " << i << endl;
                        }

                    }
                }
            }
        }
    }

    close(server_socket);
    return 0;
}
