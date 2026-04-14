#include "pki_core.h"
#include <assert.h>

// Helper to print hex for our 64-bit numbers
void print_hex(const char* label, uint64_t val) {
    printf("%-20s: 0x%016llx\n", label, (unsigned long long)val);
}

int main() {
    printf("--- 🛡️  TINYPKI CORE UNIT TESTS --- \n\n");

    // --- TEST 1: RSA MATH (The ModExp Engine) ---
    printf("[1] Testing mod_exp (2^10 mod 1000)...\n");
    // 2^10 = 1024. 1024 % 1000 = 24.
    uint64_t result = mod_exp(2, 10, 1000);
    if (result == 24) printf("✅ Math is mathing!\n");
    else printf("❌ Math failed! Got %llu\n", result);


    // --- TEST 2: SHA-64 AVALANCHE EFFECT ---
    printf("\n[2] Testing SHA-64 Avalanche Effect...\n");
    CustomCert cert1 = { .serial_number = 1001, .subject = "Alice" };
    CustomCert cert2 = { .serial_number = 1001, .subject = "Alicf" }; // Changed 'e' to 'f' (1 bit difference)

    uint64_t hash1 = sha64_hash(&cert1);
    uint64_t hash2 = sha64_hash(&cert2);

    print_hex("Hash(Alice)", hash1);
    print_hex("Hash(Alicf)", hash2);

    if (hash1 != hash2) {
        printf("✅ Success: Tiny change led to a massive hash difference!\n");
    } else {
        printf("❌ Collision detected! Something is wrong with the blender.\n");
    }


    // --- TEST 3: KEY GENERATION ---
    printf("\n[3] Testing RSA Keypair Generation...\n");
    RSA_Keypair kp;
    generate_rsa_keypair(&kp, 61, 53); // Using primes from your ca_server
    print_hex("Public n", kp.n);
    print_hex("Private d", kp.d);
    
    // Test: (e * d) mod phi must equal 1
    uint64_t phi = (61 - 1) * (53 - 1);
    if ((kp.e * kp.d) % phi == 1) {
        printf("✅ Keypair is mathematically valid ($e \\cdot d \\equiv 1 \\pmod{\\phi}$)\n");
    } else {
        printf("❌ Invalid Keypair!\n");
    }


    // --- TEST 4: INTEGRITY & TAMPER TEST ---
    printf("\n[4] Testing Signature Integrity & Tamper Protection...\n");
    
    // 1. Sign the original cert
    uint64_t sig = sign_data(hash1, kp.d, kp.n);
    cert1.signature = sig;
    printf("[*] Certificate signed.\n");

    // 2. Verify original (Should pass)
    if (verify_signature(sha64_hash(&cert1), cert1.signature, kp.e, kp.n)) {
        printf("✅ Verification: Valid cert passed.\n");
    } else {
        printf("❌ Verification: Valid cert FAILED.\n");
    }

    // 3. TAMPER: Change the serial number but keep the old signature
    cert1.serial_number = 9999; 
    printf("[!] Tampering with serial number...\n");
    
    if (!verify_signature(sha64_hash(&cert1), cert1.signature, kp.e, kp.n)) {
        printf("✅ Verification: Tampered cert REJECTED. (The bouncer is awake!)\n");
    } else {
        printf("❌ SECURITY HOLE: Tampered cert was accepted!\n");
    }

    printf("\n--- 🏁 ALL TESTS COMPLETED --- \n");
    return 0;
}