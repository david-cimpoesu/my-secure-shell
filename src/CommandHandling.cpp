#include <iostream>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <filesystem>
#include <vector>

#include "CommandHandling.h"
#include "Encryption.h"  
#include "LoginLogic.h"
#include "Globals.h" 
#include "AdminRestricted.h"       

// Executes an arbitrary shell command within the user's virtual directory and sends back the output.
void handle_random_command(int client_socket, const string& input, const unsigned char* key) { 
    if (client_sessions[client_socket].username.empty()) {
        send_encrypted_message(client_socket, (unsigned char*)"Not logged in.", 14, key);
        return;
    }

    auto it = client_virtual_dirs.find(client_socket);
    if (it == client_virtual_dirs.end()) {
        send_encrypted_message(client_socket, (unsigned char*)"Error: Virtual directory not set.", 33, key);
        return;
    }

    const string& virtual_dir = it->second;

    if (chdir(virtual_dir.c_str()) != 0) {
        perror("chdir error");
        send_encrypted_message(client_socket, (unsigned char*)"Error changing directory.", 25, key);
        return;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("Pipe error");
        send_encrypted_message(client_socket, (unsigned char*)"Error creating pipe.", 20, key);
        return;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork error");
        send_encrypted_message(client_socket, (unsigned char*)"Error creating child process.", 30, key);
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    if (pid == 0) {
       
        close(pipefd[0]); 
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execl("/bin/sh", "sh", "-c", input.c_str(), nullptr);
        perror("Execl error");
        exit(EXIT_FAILURE); 
    } else {
       
        close(pipefd[1]); 

       
        char buffer[MAX_BUFFER_SIZE];
        ssize_t bytes_read;
        string output;

        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            output += buffer;
        }
        close(pipefd[0]); 

       
        int status;
        waitpid(pid, &status, 0);

        if (output.empty() && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            output = "Command executed successfully.\n";
        } else if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            output = "Comanda inexistenta sau scrisa gresit.\n";
        }

        send_encrypted_message(client_socket, (unsigned char*)output.c_str(), output.size(), key);
    }
}

// Changes the user's current virtual working directory, supporting absolute and relative paths.
void handle_cd_command(int client_socket, const string& input, const unsigned char* key) {
    string path = input.substr(3); 
    string& virtual_dir = client_virtual_dirs[client_socket];

    if (path.empty()) {
        virtual_dir = "/";  
        send_encrypted_message(client_socket, (unsigned char*)"Changed to root directory.", 27, key);
        return;
    }

    string new_path;
    if (path[0] == '/') {
        new_path = path;  
    } else {
        new_path = virtual_dir + "/" + path;  
    }

    try {
        new_path = filesystem::canonical(new_path).string();
        virtual_dir = new_path;
        string response = "Changed directory to " + virtual_dir;
        send_encrypted_message(client_socket, (unsigned char*)response.c_str(), response.size(), key);
    } catch (const filesystem::filesystem_error& e) {
        string error = "Error changing directory: " + string(e.what());
        send_encrypted_message(client_socket, (unsigned char*)error.c_str(), error.size(), key);
    }
}

// Dispatches a received command to the appropriate handler based on its prefix or content.
void process_command(int client_socket, const string& input, fd_set& active_fds, const unsigned char* key) {
    
    cout << "[DEBUG] Command received from client: " << input << endl;

    
    if (client_sessions[client_socket].waiting_for_password) {
        cout << "[DEBUG] Client is waiting for login process to complete." << endl;

        size_t first_colon = input.find(':');
        size_t second_colon = input.find(':', first_colon + 1);

        if (first_colon == string::npos || second_colon == string::npos) {
            send_encrypted_message(client_socket, (unsigned char*)"Invalid format. Provide username and password.", 47, key);
            cout << "[DEBUG] Invalid login format received from client " << client_socket << ": " << input << endl;
            return;
        }

        string username = input.substr(first_colon + 1, second_colon - first_colon - 1);
        string password = input.substr(second_colon + 1);

        cout << "[DEBUG] Extracted username: " << username << ", password: " << password << endl;

        if (login_user(username, password)) {
            client_sessions[client_socket].waiting_for_password = false;
            client_sessions[client_socket].username = username;
            send_encrypted_message(client_socket, (unsigned char*)"Successfully logged in!", 25, key);
            cout << "[DEBUG] User " << username << " logged in successfully on client " << client_socket << endl;
        } else {
            send_encrypted_message(client_socket, (unsigned char*)"Invalid username or password.", 30, key);
            cout << "[DEBUG] Login failed for user: " << username << " on client " << client_socket << endl;
        }
        return;
    }

    if (input.find("login:") == 0) {
        cout << "[DEBUG] Login command received from client " << client_socket << endl;
        handle_login(client_socket, input, key);
    }

    else if (input == "logout") {
        cout << "[DEBUG] Logout command received from client " << client_socket << endl;
        handle_logout(client_socket, key);
    }
    
    else if (input.substr(0, 3) == "cd ") {
        cout << "[DEBUG] Change directory command received from client " << client_socket << endl;
        handle_cd_command(client_socket, input, key);
    }

    else if (input.substr(0, 9) == "add_user ") {
    cout << "[DEBUG] Add user command received from client " << client_socket << endl;
    handle_add_user(client_socket, input, key);
    }

    else if (input.substr(0, 12) == "delete_user ") {
        cout << "[DEBUG] Delete user command received from client " << client_socket << endl;
        handle_delete_user(client_socket, input, key);
    }

    else if (input == "shutdown") {
        cout << "[DEBUG] Shutdown command received from client " << client_socket << endl;
        handle_shutdown(client_socket, active_fds, key);

    }

    else if (input == "logged_users") {
        cout << "[DEBUG] Logged users command received from client " << client_socket << endl;
        handle_logged_users(client_socket, key);
    }

    else {
        cout << "[DEBUG] Other command received from client " << client_socket << ": " << input << endl;
        handle_random_command(client_socket, input, key);
    }
}
