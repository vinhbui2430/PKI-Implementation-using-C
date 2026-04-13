# Add this to your Makefile
test_pki_core: test_pki_core.c pki_core.o pki_core.h
	$(CC) $(CFLAGS) -o test_pki_core test_pki_core.c pki_core.o

# A convenient shortcut to build and run immediately
test: test_pki_core
	./test_pki_core