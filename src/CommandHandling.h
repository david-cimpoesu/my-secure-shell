#ifndef COMMAND_HANDLING_H
#define COMMAND_HANDLING_H

#include <string>
#include <sys/select.h>  // for fd_set

// Dispatches a received command to the appropriate handler based on its prefix or content.
void process_command(int client_socket, const std::string& input, fd_set& active_fds, const unsigned char* key);

// Changes the user's current virtual working directory.
void handle_cd_command(int client_socket, const std::string& input, const unsigned char* key);

// Executes a general command and sends the output.
void handle_random_command(int client_socket, const std::string& input, const unsigned char* key);

#endif // COMMAND_HANDLING_H
