#include "pki_core.h"

// Đọc danh sách đen
int is_revoked(uint64_t serial) {
    FILE *f = fopen("crl.txt", "r");
    if (!f) return 0; // File không tồn tại -> an toàn
    
    uint64_t revoked_serial;
    while (fscanf(f, "%lu", &revoked_serial) != EOF) {
        if (revoked_serial == serial) {
            fclose(f);
            return 1; // Bị thu hồi!
        }
    }
    fclose(f);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Cach su dung: ./client_verify <file_chung_thu.cert>\n");
        return 1;
    }

    printf("========== XAC THUC CHUNG THU ==========\n");

    // 1. Đọc CA Public Key
    FILE *f_pub = fopen("ca_public.key", "r");
    if (!f_pub) { printf("Loi: Khong thay CA Public Key.\n"); return 1; }
    uint64_t ca_n, ca_e;
    fscanf(f_pub, "%lu %lu", &ca_n, &ca_e);
    fclose(f_pub);

    // 2. Đọc chứng thư Client gửi đến
    FILE *f_cert = fopen(argv[1], "rb");
    if (!f_cert) { printf("Loi: Khong tim thay file %s\n", argv[1]); return 1; }
    CustomCert cert;
    fread(&cert, sizeof(CustomCert), 1, f_cert);
    fclose(f_cert);

    printf("[-] Dang kiem tra chung thu cua: %s (Serial: %lu)\n", cert.subject, cert.serial_number);

    // 3. Tính toán lại mã băm
    uint64_t computed_hash = simple_hash(&cert);
    
    // 4. Xác thực chữ ký bằng CA Public Key
    int is_valid = verify_signature(computed_hash, cert.signature, ca_e, ca_n);
    
    if (!is_valid) {
        printf("[!] CANH BAO: Chu ky gia mao hoac bi chinh sua! Tu choi truy cap.\n");
        return 1;
    }
    printf("[+] Chu ky hop le. Chung thu do Root CA cap phat.\n");

    // 5. Kiểm tra trạng thái OCSP/CRL
    if (is_revoked(cert.serial_number)) {
        printf("[!] CANH BAO OCSP: Chung thu nay nam trong danh sach den (Bi thu hoi)!\n");
        return 1;
    }

    printf("[v] HOP LE. Chuyen huong Client vao he thong an toan.\n");
    return 0;
}