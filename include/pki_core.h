#ifndef PKI_CORE_H
#define PKI_CORE_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t n; // Modulus (Public)
    uint64_t e; // Public Exponent
    uint64_t d; // Private Exponent 
} RSA_Keypair;

typedef struct {
    uint64_t serial_number;
    char issuer[64];
    char subject[64];
    uint64_t subject_pub_n;
    uint64_t subject_pub_e;
    
    // NEW: The "Validity Window"
    time_t not_before; 
    time_t not_after;   
    
    uint64_t signature;
} CustomCert; //Based on X509

// ===FUNCTION DECLARATION===
uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod);
uint64_t simple_hash(CustomCert *cert);
void generate_rsa_keypair(RSA_Keypair *kp, uint64_t p, uint64_t q);
uint64_t sign_data(uint64_t hash_val, uint64_t d, uint64_t n);
int verify_signature(uint64_t hash_val, uint64_t signature, uint64_t e, uint64_t n);

#endif