# === Variables ===
CC = gcc
CFLAGS = -Wall -Werror -g -Iinclude
LDFLAGS = -lncurses          # libraries used at link time
SRC_DIR = src
OBJ_DIR = build
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
TARGET = netwatch

# === Default rule ===
all: $(TARGET)

# === Linking ===
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# === Compiling ===
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# === Ensure build/ exists ===
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# === Clean ===
clean:
	rm -rf $(OBJ_DIR) $(TARGET)

