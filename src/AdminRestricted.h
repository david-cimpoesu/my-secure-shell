#ifndef ADMIN_RESTRICTED_H
#define ADMIN_RESTRICTED_H

#include <string>
#include <sys/select.h>

// Function declarations for admin-restricted functionalities
void handle_delete_user(int client_socket, const std::string& input, const unsigned char* key);
void handle_add_user(int client_socket, const std::string& input, const unsigned char* key);
bool add_user(const std::string& username, const std::string& password);
void handle_shutdown(int client_socket, fd_set& active_fds, const unsigned char* key);
void handle_logged_users(int client_socket, const unsigned char* key);

#endif // ADMIN_RESTRICTED_H

