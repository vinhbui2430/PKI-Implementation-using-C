#include "pki_core.h"

uint64_t mod_exp(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = (res * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return res;
}

uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    int64_t t = 0, newt = 1;
    int64_t r = phi, newr = e;
    while (newr != 0) {
        int64_t quotient = r / newr;
        int64_t temp = t;
        t = newt;
        newt = temp - quotient * newt;
        temp = r;
        r = newr;
        newr = temp - quotient * newr;
    }
    if (r > 1) return 0; 
    if (t < 0) t = t + phi;
    return (uint64_t)t;
}

void generate_rsa_keypair(RSA_Keypair *kp, uint64_t p, uint64_t q) {
    kp->n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    kp->e = 3;
    while (gcd(kp->e, phi) != 1) {
        kp->e += 2;
    }
    kp->d = mod_inverse(kp->e, phi);
}

// sha64
uint64_t simple_hash(CustomCert *cert) {
    uint64_t h = 0x6a09e667f3bcc908ULL; 
    
    char buffer[256];
    
    sprintf(buffer, "%llu%s%s%llu%llu", cert->serial_number, cert->issuer, cert->subject, cert->subject_pub_n, cert->subject_pub_e);
    printf("\n[DEBUG HASH] Dang bam chung thu Serial: %llu\n", cert->serial_number);
    printf("[DEBUG HASH] Buffer content: [%s]\n", buffer);
    printf("[DEBUG HASH] Buffer length: %zu\n\n", strlen(buffer));

    unsigned char *data = (unsigned char *)buffer;
    size_t len = strlen(buffer);

    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h = (h ^ _rotr(h, 25)) ^ (h ^ _rotr(h, 41));
        h = h * 0xd6e8feb86659fd93ULL; 
        h += 0xbb67ae8584caa73bULL;   
    }
    //MurmurHash3 copycat
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL; 
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33; 
    return h;
}

/* sha64_hash 1version
uint64_t sha64_hash(CustomCert *cert) {
    // 1. Initial State 
    uint64_t h = 0x6a09e667f3bcc908ULL; 
    
    // We treat the certificate struct as a stream of bytes
    unsigned char *data = (unsigned char *)cert;
    size_t len = sizeof(CustomCert);

    // 3. The Smoothie
    for (size_t i = 0; i < len; i++) {
        // Mix in the current byte
        h ^= data[i];
        // Perform bitwise cartwheel (inspired by SHA-2 core)
        h = (h ^ rotr(h, 25)) ^ (h ^ rotr(h, 41));
        h = h * 0xd6e8feb86659fd93ULL; // A HUGE prime multiplier
        h += 0xbb67ae8584caa73bULL;   // Another "unga bunga" constant
    }

    // 4. Final Constraints
    // This isn't exactly SHA-256 but it is to my smol brain
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL; // STONKING prime constant
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33; //MurmurHash3 copycat
    return h;
} 
*/

uint64_t sign_data(uint64_t hash_val, uint64_t d, uint64_t n) {
    return mod_exp(hash_val, d, n);
}

int verify_signature(uint64_t hash_val, uint64_t signature, uint64_t e, uint64_t n) {
    uint64_t decrypted_hash = mod_exp(signature, e, n);
    return (decrypted_hash == (hash_val % n));
}