CC = gcc
CFLAGS = -Wall -O2 -Iinclude
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# List of objects
OBJS = $(OBJ_DIR)/pki_core.o $(OBJ_DIR)/csr_helper.o

all: setup ca_server ra_issuer client_verify

setup:
	mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

ca_server: $(SRC_DIR)/ca_server.c $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/ca_server $^

ra_issuer: $(SRC_DIR)/ra_issuer.c $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/ra_issuer $^

client_verify: $(SRC_DIR)/client_verify.c $(OBJS)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/client_verify $^

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) vault/ *.cert crl.txt


test_pki_core: test_pki_core.c pki_core.o pki_core.h
	$(CC) $(CFLAGS) -o test_pki_core test_pki_core.c pki_core.o

# A convenient shortcut to build and run immediately
test: test_pki_core
	./test_pki_core