#include <iostream>
#include <string>
#include <map>
#include <set>
#include <sqlite3.h>
#include <bcrypt/BCrypt.hpp>
#include <signal.h>
#include <sys/wait.h>

#include "AdminRestricted.h"
#include "Encryption.h" 
#include "Globals.h"     
#include "LoginLogic.h"

void handle_delete_user(int client_socket, const string& input, const unsigned char* key) {
    
    if (client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Not logged in.", 14, key);
        return;
    }

    if (!client_sessions[client_socket].is_admin) {
        send_encrypted_message(client_socket, (unsigned char*)"Admin privileges required.", 25, key);
        return;
    }

    string username = input.substr(12); 
    if (username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Invalid format. Use 'delete_user <username>'.", 47, key);
        return;
    }

    sqlite3* db;
    sqlite3_stmt* stmt;
    int status;

    status = sqlite3_open_v2("users_database.db", &db, SQLITE_OPEN_READWRITE, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error opening database: " << sqlite3_errmsg(db) << endl;
        send_encrypted_message(client_socket, (unsigned char*)"Failed to open database.", 23, key);
        return;
    }

    const char* interogare = "SELECT username FROM users;";
    status = sqlite3_prepare_v2(db, interogare, -1, &stmt, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error preparing SELECT statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        send_encrypted_message(client_socket, (unsigned char*)"Nu s-a putut executa interogarea.", 33, key);
        return;
    }

    bool user_found = false;
    string hashed_username;

    while ((status = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* stored_username_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (BCrypt::validatePassword(username, stored_username_hash)) {
            user_found = true;
            hashed_username = stored_username_hash; 
            break;
        }
    }
    sqlite3_finalize(stmt);

    if (!user_found) {
        send_encrypted_message(client_socket, (unsigned char*)"User not found.", 15, key);
        sqlite3_close(db);
        return;
    }

    const char* query_delete = "DELETE FROM users WHERE username = ?;";
    status = sqlite3_prepare_v2(db, query_delete, -1, &stmt, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error preparing DELETE statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        send_encrypted_message(client_socket, (unsigned char*)"Failed to execute delete query.", 31, key);
        return;
    }

    status = sqlite3_bind_text(stmt, 1, hashed_username.c_str(), -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error binding hashed username: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        send_encrypted_message(client_socket, (unsigned char*)"Failed to bind username.", 24, key);
        return;
    }

    
    status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        cerr << "[ERROR] Error executing DELETE query: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        send_encrypted_message(client_socket, (unsigned char*)"Failed to delete user.", 23, key);
        return;
    }

    cout << "[DEBUG] User " << username << " deleted successfully." << endl;
    send_encrypted_message(client_socket, (unsigned char*)"User deleted successfully.", 25, key);

    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// Adds a new user to the database if not already present; restricted to admins.
void handle_add_user(int client_socket, const string& input, const unsigned char* key) {
    
    if (client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Not logged in.", 14, key);
        return;
    }

    if (!client_sessions[client_socket].is_admin) {
        send_encrypted_message(client_socket, (unsigned char*)"Admin privileges required.", 25, key);
        return;
    }

    size_t first_space = input.find(' ', 9);
    if (first_space == string::npos) {
        send_encrypted_message(client_socket, (unsigned char*)"Invalid format. Use 'add_user <username> <password>'.", 51, key);
        return;
    }
    string username = input.substr(9, first_space - 9);
    string password = input.substr(first_space + 1);

    if (verif_username(username)) {
        send_encrypted_message(client_socket, (unsigned char*)"Username already exists.", 25, key);
        return;
    }

    if (add_user(username, password)) {
        send_encrypted_message(client_socket, (unsigned char*)"User added successfully.", 23, key);
    } else {
        send_encrypted_message(client_socket, (unsigned char*)"Failed to add user. Check the logs for details.", 48, key);
    }
}

// Hashes and inserts a new user’s credentials into the database
bool add_user(const string& username, const string& password) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    int status;

    cout << "[DEBUG] Starting user addition for username: " << username << endl;

    status = sqlite3_open_v2("users_database.db", &db, SQLITE_OPEN_READWRITE, NULL);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error opening database (it might not exist): " << sqlite3_errmsg(db) << endl;
        return false;
    }

    cout << "[DEBUG] Database connection opened successfully." << endl;

    string hashed_username = BCrypt::generateHash(username);
    string hashed_password = BCrypt::generateHash(password);

    cout << "[DEBUG] Hashed username: " << hashed_username << endl;
    cout << "[DEBUG] Hashed password: " << hashed_password << endl;

    const char* interogare = "INSERT INTO users (username, password) VALUES (?, ?);";
    status = sqlite3_prepare_v2(db, interogare, -1, &stmt, NULL);
    if (status!= SQLITE_OK) {
        cerr << "[ERROR] Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return false;
    }

    status = sqlite3_bind_text(stmt, 1, hashed_username.c_str(), -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error binding hashed username: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    status = sqlite3_bind_text(stmt, 2, hashed_password.c_str(), -1, SQLITE_STATIC);
    if (status != SQLITE_OK) {
        cerr << "[ERROR] Error binding hashed password: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    status = sqlite3_step(stmt);
    if (status != SQLITE_DONE) {
        cerr << "[ERROR] Error inserting data: " << sqlite3_errmsg(db) << endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    cout << "[DEBUG] User added successfully." << endl;

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}

//Shuts down the server and all client sessions, restricted to admins.
void handle_shutdown(int client_socket, fd_set& active_fds, const unsigned char* key) {
    if (client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Not logged in.", 14, key);
        return;
    }

    if (!client_sessions[client_socket].is_admin) {
        send_encrypted_message(client_socket, (unsigned char*)"Admin privileges required.", 25, key);
        return;
    }

    cout << "[INFO] Initiating server shutdown..." << endl;

    for (auto& session : client_sessions) {
        send_encrypted_message(session.first, (unsigned char*)"Server is shutting down.", 24, key);
        shutdown(session.first, SHUT_RDWR); 
        close(session.first);              
        FD_CLR(session.first, &active_fds); 
    }

    client_sessions.clear();
    logged_in_users.clear();

    close(server_socket);

    pid_t pid;
    while ((pid = waitpid(-1, nullptr, WNOHANG)) > 0) {
        if (kill(pid, SIGINT) == 0) {
            cout << "[INFO] Sent SIGINT to child process " << pid << "." << endl;
        } else {
            perror("[ERROR] Failed to send SIGINT to child process");
        }
    }

    cout << "[INFO] Server shut down successfully." << endl;
    exit(0);
}

// Sends the list of currently logged-in users to an admin client.
void handle_logged_users(int client_socket, const unsigned char* key) {
    
    if (client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Not logged in.", 14, key);
        return;
    }

    if (!client_sessions[client_socket].is_admin) {
        send_encrypted_message(client_socket, (unsigned char*)"Admin privileges required.", 25, key);
        return;
    }

    string response = "Logged users:\n";
    for (const auto& user : logged_in_users) {
        response += "- " + user + "\n";
    }

    send_encrypted_message(client_socket, (unsigned char*)response.c_str(), response.size(), key);
}
