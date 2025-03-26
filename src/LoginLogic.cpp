#include <iostream>
#include <cstring>
#include <sqlite3.h>
#include <bcrypt/BCrypt.hpp>
#include <map>

#include "LoginLogic.h" 
#include "Globals.h"
#include "Encryption.h"

// Checks if a given username exists in the database using bcrypt hash validation
bool verif_username(const std::string& username) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int status;

    status = sqlite3_open_v2("users_database.db", &db, SQLITE_OPEN_READONLY, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Failed to open database: " << sqlite3_errmsg(db) << endl;
        return false;
    }

    const char* interogare = "SELECT username FROM users;";
    status = sqlite3_prepare_v2(db, interogare, -1, &stmt, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Failed to prepare statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }

    
    while ((status = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* stored_username_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

        if (BCrypt::validatePassword(username, stored_username_hash)) {
            cout << "[DEBUG] Username already exists: " << username << endl;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return true;  
        }
    }

    
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    cout << "[DEBUG] Username does not exist: " << username << endl;
    return false;  
}

// Authenticates a user by checking the hashed username and password against the database
bool login_user(const string& username, const string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int status;

    cout << "[DEBUG] Starting Login for username: " << username << endl;

    status = sqlite3_open_v2("users_database.db", &db, SQLITE_OPEN_READWRITE, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error opening database (it might not exist): " << sqlite3_errmsg(db) << endl;
        return false;
    }

    cout << "[DEBUG] Database connection opened successfully." << endl;

    const char* interogare = "SELECT username, password FROM users;";
    status = sqlite3_prepare_v2(db, interogare, -1, &stmt, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }

    // Parcurge toate rândurile din baza de date
    while ((status = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char* stored_username_hash = sqlite3_column_text(stmt, 0);
        const unsigned char* stored_password_hash = sqlite3_column_text(stmt, 1);

        if (BCrypt::validatePassword(username, string(reinterpret_cast<const char*>(stored_username_hash)))) {
            
            if (BCrypt::validatePassword(password, string(reinterpret_cast<const char*>(stored_password_hash)))) {
                cout << "[DEBUG] Login successful for username: " << username << endl;
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return true;
            } else {
                cout << "[DEBUG] Login failed: Password mismatch for username: " << username << endl;
                sqlite3_finalize(stmt);
                sqlite3_close(db);
                return false;
            }
        }
    }

    // Daca am parcurs toate randurile si nu am gasit username-ul
    cout << "[DEBUG] Login failed: Username not found." << endl;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    cout << "[DEBUG] Database connection closed." << endl;

    return false;
}

// Handles the login process: extracts credentials, authenticates user, and assigns session state.
void handle_login(int client_socket, const string& input, const unsigned char* key) {
    
    size_t pos = input.find("login:");
    if (!(pos == 0)) {
        send_encrypted_message(client_socket, (unsigned char*)"Invalid command format. Use 'login:username password'.", 53, key);
        return;
    }

    string user_data;
    user_data = input.substr(6); 

    size_t space_pos = user_data.find(' ');
    if (space_pos == string::npos) {
        send_encrypted_message(client_socket, (unsigned char*)"Invalid format. Provide username and password.", 47, key);
        return;
    }

    string username;
    string password;
    username = user_data.substr(0, space_pos);
    password = user_data.substr(space_pos + 1);

    
    if (!client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"You are already logged in. Logout first to switch users.", 56, key);
        return;
    }

    
    if (logged_in_users.find(username) != logged_in_users.end()) {
        send_encrypted_message(client_socket, (unsigned char*)"This user is already logged in elsewhere.", 43, key);
        return;
    }

    bool is_authenticated = login_user(username, password);
    if (is_authenticated) {
        client_sessions[client_socket].username = username;
        logged_in_users.insert(username); 

        sqlite3* db;
        sqlite3_stmt* stmt;
        int status = 0;

        status = sqlite3_open_v2("users_database.db", &db, SQLITE_OPEN_READONLY, NULL);
        if (!(status != SQLITE_OK)) {
            const char* interogare = "SELECT username, is_admin FROM users;";

            status = sqlite3_prepare_v2(db, interogare, -1, &stmt, NULL);
            for (; status == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW;) {
                const char* stored_username_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                int is_admin = sqlite3_column_int(stmt, 1);

                if (BCrypt::validatePassword(username, stored_username_hash)) {
                    client_sessions[client_socket].is_admin = (is_admin == 1);
                    if (client_sessions[client_socket].is_admin) {
                        send_encrypted_message(client_socket, (unsigned char*)"Welcome back, admin!", 21, key);
                    } else {
                        send_encrypted_message(client_socket, (unsigned char*)"Login successful!", 18, key);
                    }
                    break;
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    } else {
        send_encrypted_message(client_socket, (unsigned char*)"Invalid username or password.", 29, key);
    }
}

// Logs the user out by clearing their session and removing them from the active users set.
void handle_logout(int client_socket, const unsigned char* key) {
    string username = client_sessions[client_socket].username;

    if (username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Already logged out.", 19, key);
    } else {
        client_sessions.erase(client_socket);
        logged_in_users.erase(username); 
        send_encrypted_message(client_socket, (unsigned char*)"Successfully logged out.", 25, key);
    }
}
