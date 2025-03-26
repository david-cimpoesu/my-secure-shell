CXX = g++
CXXFLAGS = -Wall -Wextra -std=c++17
LDFLAGS = -lsqlite3 -lssl -lcrypto -lbcrypt -lcrypt
SRC_DIR = src
BUILD_DIR = build

COMMON_SRC = \
  $(SRC_DIR)/AdminRestricted.cpp \
  $(SRC_DIR)/CommandHandling.cpp \
  $(SRC_DIR)/LoginLogic.cpp \
  $(SRC_DIR)/Encryption.cpp \
  $(SRC_DIR)/Globals.cpp

SERVER_SRC = $(SRC_DIR)/SSH_SERVER.cpp
CLIENT_SRC = $(SRC_DIR)/SSH_CLIENT.cpp

SERVER_OBJ = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(COMMON_SRC) $(SERVER_SRC))
CLIENT_OBJ = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(COMMON_SRC) $(CLIENT_SRC))

all: SSH_SERVER SSH_CLIENT

SSH_SERVER: $(SERVER_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

SSH_CLIENT: $(CLIENT_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) SSH_SERVER SSH_CLIENT

.PHONY: all clean

