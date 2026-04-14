#include "pki_core.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
<<<<<<< HEAD
        printf("Cach su dung: ./ra_issuer.exe <Ten_Client>\n");
=======
        printf("Cach su dung: ./ra_issuer <Ten_Client>\n");
>>>>>>> 28f77f5 (Saving progress before cleanup)
        return 1;
    }
    char *client_name = argv[1];

    printf("========== CAP PHAT CHUNG THU CHO %s ==========\n", client_name);

<<<<<<< HEAD
    FILE *f_ca = fopen("ca_private.key", "r");
    if (!f_ca) { printf("Loi: Khong tim thay CA key!\n"); return 1; }
    
    RSA_Keypair ca_key;
    // Dùng %llu cho Windows
    fscanf(f_ca, "%llu %llu %llu", &ca_key.n, &ca_key.e, &ca_key.d);
    fclose(f_ca);

    RSA_Keypair client_key;
    generate_rsa_keypair(&client_key, 17, 19); 

    CustomCert cert;
    cert.serial_number = time(NULL) % 10000; 
=======
    // 1. Đọc khóa CA (Chỉ RA mới có quyền đọc file này)
    FILE *f_ca = fopen("ca_private.key", "r");
    if (!f_ca) { printf("Loi: Khong tim thay CA key!\n"); return 1; }
    RSA_Keypair ca_key;
    fscanf(f_ca, "%lu %lu %lu", &ca_key.n, &ca_key.e, &ca_key.d);
    fclose(f_ca);

    // 2. Tạo khóa cho Client (Ví dụ Client dùng 2 số nguyên tố khác)
    RSA_Keypair client_key;
    generate_rsa_keypair(&client_key, 17, 19); 

    // 3. Build Chứng thư
    CustomCert cert;
    cert.serial_number = time(NULL) % 10000; // Random serial based on time
>>>>>>> 28f77f5 (Saving progress before cleanup)
    strcpy(cert.issuer, "My_Custom_Root_CA");
    strcpy(cert.subject, client_name);
    cert.subject_pub_n = client_key.n;
    cert.subject_pub_e = client_key.e;
<<<<<<< HEAD
    cert.signature = 0;

    // ĐỔI TÊN HÀM Ở ĐÂY CHO KHỚP VỚI FILE CORE CỦA BẠN KIA
    uint64_t cert_hash = sha64_hash(&cert); 
    cert.signature = sign_data(cert_hash, ca_key.d, ca_key.n); 

=======

    // 4. RA yêu cầu CA ký lên chứng thư
    uint64_t cert_hash = simple_hash(&cert);
    cert.signature = sign_data(cert_hash, ca_key.d, ca_key.n); // Ký bằng CA Private Key

    // 5. Ghi chứng thư ra file
>>>>>>> 28f77f5 (Saving progress before cleanup)
    char cert_filename[256];
    sprintf(cert_filename, "%s.cert", client_name);
    FILE *f_cert = fopen(cert_filename, "wb");
    fwrite(&cert, sizeof(CustomCert), 1, f_cert);
    fclose(f_cert);

<<<<<<< HEAD
    printf("[+] Da tao khoa cho Client: N=%llu, E=%llu\n", client_key.n, client_key.e);
    printf("[+] Ma bam (Hash) cua Chung thu: %llu\n", cert_hash);
    printf("[+] Chu ky cua CA: %llu\n", cert.signature);
=======
    printf("[+] Da tao khoa cho Client: N=%lu, E=%lu\n", client_key.n, client_key.e);
    printf("[+] Ma bam (Hash) cua Chung thu: %lu\n", cert_hash);
    printf("[+] Chu ky cua CA: %lu\n", cert.signature);
>>>>>>> 28f77f5 (Saving progress before cleanup)
    printf("[v] Da xuat chung thu ra file: %s\n", cert_filename);

    return 0;
}