# My Secure Shell (SSH)

## Project Overview

My Secure Shell is a custom secure shell solution developed as part of the "Computer Networks" course (Year 2, Semester 1) at UAIC FII. It enables secure communication over TCP between a server and multiple clients using layered cryptographic mechanisms.

The system emulates the behavior of real-world SSH implementations by integrating all three major cryptographic components:

- Asymmetric encryption (RSA): A session key is securely exchanged at the start of every connection.
- Symmetric encryption (AES-128, ECB mode): All communication after the key exchange is encrypted using the shared key.
- Secure hashing (bcrypt): Passwords are hashed and securely verified during login.

User data is managed using a local SQLite database, offering portable and efficient file-based storage.

---

## Compilation

Make sure you are in the root directory of the project and type:

    make

This will generate two executables:

- `SSH_SERVER` — the server application
- `SSH_CLIENT` — the client application

---

## Required Libraries

Ensure the following libraries are installed on your system:

1. OpenSSL
2. SQLite
3. libbcrypt
4. Development headers such as `sqlite3.h` (usually included in `libsqlite3-dev`)

---

## Usage Instructions

### Step 1: Start the Server

    ./SSH_SERVER

### Step 2: Connect from the Client

    ./SSH_CLIENT

### Step 3: Login

Use the following syntax:

    login:<username> <password>

The system comes with two predefined users stored in `users_database.db`:

- randomuser1 / password1 → admin privileges
- randomuser2 / password2 → regular user

### Step 4: Set a Working Directory

Before executing commands, users must specify a working directory:

    cd <directory-path>

### Step 5: Run Commands

Any valid, non-interactive OS command can be executed (e.g., `ls`, `mkdir`, `cat`, `rm`, etc.).

Note: Interactive programs like `nano`, `man`, or `top` are not supported.

### Step 6: Terminate the Session

Use `Ctrl+C` to disconnect from the server and terminate the session.

---

## Admin-Only Commands

Users with administrative rights have access to the following commands:

- `add_user <username> <password>` 
  Adds a new user to the database.

- `delete_user <username>` 
  Removes an existing user from the database.

- `logged_users` 
  Displays all currently logged-in users.

- `shutdown` 
  Gracefully shuts down the server and disconnects all clients.

---

## Bibliography

1. OpenSSL Documentation – https://www.openssl.org/docs/
2. SQLite Documentation – https://sqlite.org/docs.html
3. bcrypt GitHub Repository – https://github.com/trusch/libbcrypt
4. Secure Shell (Wikipedia) – https://en.wikipedia.org/wiki/Secure_Shell
5. chdir() Function Reference – https://www.geeksforgeeks.org/chdir-in-c-language-with-examples/
6. PlantUML – https://plantuml.com/
7. TCP Server-Client Basics (UAIC Course) – https://edu.info.uaic.ro/computer-networks/cursullaboratorul.php

