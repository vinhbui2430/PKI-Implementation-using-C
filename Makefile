CC = gcc
CFLAGS = -Wall -O2 -Iinclude
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# List of objects
COMMON_OBJS = $(OBJ_DIR)/pki_core.o 
all: setup ca_server ra_issuer client_verify

setup:
# 	mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(OBJ_DIR)/pki_core.o: $(SRC_DIR)/pki_core.c
	$(CC) $(CFLAGS) -c $< -o $@

ca_server: $(SRC_DIR)/ca_server.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/ca_server $(SRC_DIR)/ca_server.c $(CORE_OBJ)

ra_issuer: $(SRC_DIR)/ra_issuer.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/ra_issuer $(SRC_DIR)/ra_issuer.c $(CORE_OBJ)

client_verify: $(SRC_DIR)/client_verify.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/client_verify $(SRC_DIR)/client_verify.c $(CORE_OBJ)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) vault/ *.cert crl.txt

# ===TESTBAND===
test_pki_core: test_pki_core.c pki_core.o pki_core.h
	$(CC) $(CFLAGS) -o test_pki_core test_pki_core.c pki_core.o

# A convenient shortcut to build and run immediately
test: test_pki_core
	./test_pki_core