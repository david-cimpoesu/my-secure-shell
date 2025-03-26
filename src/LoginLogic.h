#ifndef LOGIN_LOGOUT_H
#define LOGIN_LOGOUT_H

#include <string>

// Checks if a given username exists in the database using bcrypt hash validation
bool verif_username(const std::string& username);

// Authenticates the user with the provided username and password.
bool login_user(const std::string& username, const std::string& password);

// Handles the login process for a connected client.
void handle_login(int client_socket, const std::string& input, const unsigned char* key);

// Handles the logout process for a connected client.
void handle_logout(int client_socket, const unsigned char* key);

#endif // LOGIN_LOGOUT_H
