#include "pki_core.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Cach su dung: ./ra_issuer.exe <Ten_Client>\n");
        return 1;
    }
    char *client_name = argv[1];

    printf("========== CAP PHAT CHUNG THU CHO %s ==========\n", client_name);

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
    strcpy(cert.issuer, "My_Custom_Root_CA");
    strcpy(cert.subject, client_name);
    cert.subject_pub_n = client_key.n;
    cert.subject_pub_e = client_key.e;

    // 4. RA yêu cầu CA ký lên chứng thư
    uint64_t cert_hash = simple_hash(&cert);
    cert.signature = sign_data(cert_hash, ca_key.d, ca_key.n); // Ký bằng CA Private Key

    // 5. Ghi chứng thư ra file
    char cert_filename[256];
    sprintf(cert_filename, "%s.cert", client_name);
    FILE *f_cert = fopen(cert_filename, "wb");
    fwrite(&cert, sizeof(CustomCert), 1, f_cert);
    fclose(f_cert);

    printf("[+] Da tao khoa cho Client: N=%llu, E=%llu\n", client_key.n, client_key.e);
    printf("[+] Ma bam (Hash) cua Chung thu: %llu\n", cert_hash);
    printf("[+] Chu ky cua CA: %llu\n", cert.signature);
    printf("[v] Da xuat chung thu ra file: %s\n", cert_filename);

    return 0;
}