#include "pki_core.h"

// Thuật toán Lũy thừa Module (a^b mod m) - Cốt lõi của RSA
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

// Thuật toán Euclid tìm ước chung lớn nhất (GCD)
uint64_t gcd(uint64_t a, uint64_t b) {
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Thuật toán Euclid mở rộng tìm khóa bí mật (d) sao cho (d*e) % phi == 1
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
    if (r > 1) return 0; // Không thể nghịch đảo
    if (t < 0) t = t + phi;
    return (uint64_t)t;
}

// Tạo cặp khóa RSA từ 2 số nguyên tố p và q
void generate_rsa_keypair(RSA_Keypair *kp, uint64_t p, uint64_t q) {
    kp->n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    
    // Chọn e nhỏ nhất nguyên tố cùng nhau với phi
    kp->e = 3;
    while (gcd(kp->e, phi) != 1) {
        kp->e += 2;
    }
    
    // Tính d
    kp->d = mod_inverse(kp->e, phi);
}

// Hàm Băm (Hash) đơn giản: DJB2 algorithm biến đổi string & số thành 1 số uint64_t
uint64_t simple_hash(CustomCert *cert) {
    uint64_t hash = 5381;
    int c;
    char buffer[256];
    sprintf(buffer, "%lu%s%s%lu%lu", cert->serial_number, cert->issuer, cert->subject, cert->subject_pub_n, cert->subject_pub_e);
    
    char *str = buffer;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    }
    return hash;
}

// Ký điện tử: S = Hash^d mod n
uint64_t sign_data(uint64_t hash_val, uint64_t d, uint64_t n) {
    return mod_exp(hash_val, d, n);
}

// Xác thực chữ ký: Hash == S^e mod n ?
int verify_signature(uint64_t hash_val, uint64_t signature, uint64_t e, uint64_t n) {
    uint64_t decrypted_hash = mod_exp(signature, e, n);
    return (decrypted_hash == hash_val);
}