#include "pki_core.h"

int main() {
    printf("========== KHOI TAO ROOT CA ==========\n");
    RSA_Keypair ca_key;
    
    // Chọn 2 số nguyên tố (Trong thực tế p,q dài hàng trăm chữ số, sinh ngẫu nhiên)
    // Ở đây fix cứng để test toán học không bị tràn bộ nhớ uint64_t
    uint64_t p = 61; 
    uint64_t q = 53; 
    
    printf("[*] Dang tinh toan cap khoa RSA cho CA...\n");
    generate_rsa_keypair(&ca_key, p, q);
    
    printf("[+] CA Public Key (n, e) : (%lu, %lu)\n", ca_key.n, ca_key.e);
    printf("[!] CA Private Key (d)   : %lu (Giu bi mat tuyet doi!)\n", ca_key.d);

    // Lưu khóa bí mật của CA (Mô phỏng lưu vào vùng cấm)
    FILE *f_priv = fopen("ca_private.key", "w");
    fprintf(f_priv, "%lu %lu %lu", ca_key.n, ca_key.e, ca_key.d);
    fclose(f_priv);

    // Lưu Public Key của CA để mọi người cùng biết
    FILE *f_pub = fopen("ca_public.key", "w");
    fprintf(f_pub, "%lu %lu", ca_key.n, ca_key.e);
    fclose(f_pub);

    printf("[v] Da hoan tat setup CA. File duoc luu tai thu muc hien tai.\n");
    return 0;
}