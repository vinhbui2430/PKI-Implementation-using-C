#include <stdio.h>
#include "pki_core.h"
#include "test_ca_server.h"

// ===== TEST: Tạo CA =====
void test_generate_ca() {
    printf("\n===== TEST: GENERATE CA =====\n");

    RSA_Keypair ca_key;

    uint64_t p = 61;
    uint64_t q = 53;

    generate_rsa_keypair(&ca_key, p, q);

    printf("Public Key (n, e): (%lu, %lu)\n", ca_key.n, ca_key.e);
    printf("Private Key (d): %lu\n", ca_key.d);
}


// ===== TEST: Ký certificate =====
void test_sign_certificate() {
    printf("\n===== TEST: SIGN CERTIFICATE =====\n");

    RSA_Keypair ca_key;
    RSA_Keypair client_key;

    // CA key
    generate_rsa_keypair(&ca_key, 61, 53);

    // Client key
    generate_rsa_keypair(&client_key, 47, 59);

    // Giả lập certificate = ký public key client
    uint64_t message = client_key.e;

    uint64_t signature = mod_exp(message, ca_key.d, ca_key.n);

    printf("Client Public e: %lu\n", message);
    printf("Signature: %lu\n", signature);

    // Verify
    uint64_t verify = mod_exp(signature, ca_key.e, ca_key.n);

    printf("Verify result: %lu\n", verify);

    if (verify == message)
        printf("✔ Certificate VALID\n");
    else
        printf("✘ Certificate INVALID\n");
}


// ===== MAIN TEST =====
int main() {
    printf("========== PKI TEST ==========\n");

    test_generate_ca();
    test_sign_certificate();

    return 0;
}