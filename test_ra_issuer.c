#include "test_ra_issuer.h"

void run_cert_test(const char *filename) {
    FILE *f_cert = fopen(filename, "rb");
    if (!f_cert) {
        printf("[-] LOI: Khong mo duoc file %s\n", filename);
        return;
    }

    CustomCert cert;
    fread(&cert, sizeof(CustomCert), 1, f_cert);
    fclose(f_cert);

    printf("\n=== KET QUA TEST ===\n");
    printf("[+] Subject: %s\n", cert.subject);
    printf("[+] Public N: %llu\n", cert.subject_pub_n);
    printf("[+] Signature: %llu\n", cert.signature);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    run_cert_test(argv[1]);
    return 0;
}