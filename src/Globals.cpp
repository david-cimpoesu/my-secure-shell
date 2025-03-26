#include "Globals.h"

int server_socket;
int max_fd;

map<int, string> client_virtual_dirs;
set<string> logged_in_users;
map<int, ClientSession> client_sessions;

