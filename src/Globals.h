#pragma once
#include <string>
#include <map>
#include <set>
#include <netinet/in.h> // pentru sockaddr_in

#define PORT 2727
#define MAX_BUFFER_SIZE 1024
#define MAX_CLIENTS 10

using namespace std;

extern int server_socket;
extern int max_fd;

extern map<int, string> client_virtual_dirs;

extern set<string> logged_in_users;

struct ClientSession {
    string username;
    bool waiting_for_password = false;
    bool is_admin = false; 
};

extern map<int, ClientSession> client_sessions;
