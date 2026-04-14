#ifndef CSR_H
#define CSR_H

/* =============================================================================
 * csr.h — Certificate Storage & Request Helper
 * =============================================================================
 * Module bổ trợ cho ca_server.c, tăng cường độ bền vững bằng cách cung cấp:
 *   1. Quản lý thư mục lưu khóa (keys/ directory)
 *   2. Lớp kiểm soát quyền truy cập file (ACL tối giản trên filesystem)
 *   3. Xuất/nhập keypair an toàn với kiểm tra lỗi đầy đủ
 *   4. Xử lý các trường hợp ngoại lệ (file tồn tại, permission denied, v.v.)
 * =============================================================================
 * Sử dụng:
 *   #include "pki_core.h"
 *   #include "csr.h"
 *
 *   // Khởi tạo kho khóa
 *   KeyStore ks;
 *   if (csr_init_keystore(&ks, "keys") != CSR_OK) { ... }
 *
 *   // Lưu CA keypair với quyền OWNER_ONLY
 *   csr_export_keypair(&ks, &ca_kp, "ca", KP_PRIVATE, PERM_OWNER_ONLY);
 *   csr_export_keypair(&ks, &ca_kp, "ca", KP_PUBLIC,  PERM_PUBLIC_READ);
 *
 *   // Đọc lại với kiểm tra quyền
 *   RSA_Keypair loaded;
 *   if (csr_import_keypair(&ks, &loaded, "ca", KP_PRIVATE) != CSR_OK) { ... }
 * =============================================================================
 */

#include "pki_core.h"

#include <sys/stat.h>   /* mkdir, stat, chmod */
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
  #include <direct.h>   /* _mkdir */
  #include <io.h>       /* _access */
  #define MKDIR(path) _mkdir(path)
  #define ACCESS(path, mode) _access(path, mode)
  #define ACCESS_READ  4
  #define ACCESS_WRITE 2
  /* Windows không có chmod POSIX; dùng _chmod từ <sys/stat.h> */
  #define CHMOD(path, mode) _chmod(path, mode)
  #define PATH_SEP "\\"
#else
  #include <unistd.h>   /* access(), R_OK, W_OK */
  #define MKDIR(path) mkdir(path, 0700)
  #define ACCESS(path, mode) access(path, mode)
  #define ACCESS_READ  R_OK
  #define ACCESS_WRITE W_OK
  #define CHMOD(path, mode) chmod(path, mode)
  #define PATH_SEP "/"
#endif

/* ── Giới hạn kích thước ──────────────────────────────────────────────────── */
#define CSR_PATH_MAX   256   /* độ dài tối đa của đường dẫn */
#define CSR_NAME_MAX   64    /* độ dài tối đa của tên định danh khóa */
#define CSR_AUDIT_MAX  512   /* kích thước buffer dòng audit log */

/* ── Mã trả về ────────────────────────────────────────────────────────────── */
typedef enum {
    CSR_OK              =  0,   /* thành công */
    CSR_ERR_NULLPTR     = -1,   /* con trỏ NULL được truyền vào */
    CSR_ERR_PATH        = -2,   /* đường dẫn không hợp lệ hoặc quá dài */
    CSR_ERR_MKDIR       = -3,   /* không thể tạo thư mục */
    CSR_ERR_EXISTS      = -4,   /* file đã tồn tại (dùng force=1 để ghi đè) */
    CSR_ERR_NOT_FOUND   = -5,   /* file không tìm thấy */
    CSR_ERR_PERMISSION  = -6,   /* không đủ quyền truy cập */
    CSR_ERR_IO          = -7,   /* lỗi đọc/ghi file */
    CSR_ERR_CORRUPT     = -8,   /* file khóa bị hỏng (sai format) */
    CSR_ERR_OVERFLOW    = -9,   /* tên quá dài, buffer overflow */
    CSR_ERR_KEYSIZE     = -10,  /* modulus n quá nhỏ (< CSR_MIN_MODULUS) */
} CSR_Status;

/* ── Quyền truy cập file ─────────────────────────────────────────────────── */
typedef enum {
    PERM_OWNER_ONLY  = 0600,   /* chỉ owner đọc/ghi — dành cho private key */
    PERM_PUBLIC_READ = 0644,   /* owner đọc/ghi, others chỉ đọc — public key */
    PERM_READ_ONLY   = 0444,   /* chỉ đọc cho mọi người — file đã đóng băng */
} CSR_Permission;

/* ── Loại khóa xuất ──────────────────────────────────────────────────────── */
typedef enum {
    KP_PRIVATE = 0,   /* xuất đủ bộ 3 (n, e, d) */
    KP_PUBLIC  = 1,   /* chỉ xuất (n, e) */
} CSR_KeyPart;

/* ── Struct KeyStore ─────────────────────────────────────────────────────── */
/*
 * KeyStore đại diện cho một thư mục lưu trữ khóa có quản lý.
 * Tất cả thao tác xuất/nhập đều đi qua struct này.
 */
typedef struct {
    char base_dir[CSR_PATH_MAX];   /* đường dẫn thư mục gốc, ví dụ: "keys" */
    int  initialized;              /* cờ kiểm tra đã gọi csr_init_keystore() */
    FILE *audit_log;               /* file audit log (NULL = tắt) */
} KeyStore;

/* ── Kiểm tra modulus tối thiểu ─────────────────────────────────────────── */
/*
 * n = p*q với p=17, q=19 cho ra n=323.
 * n với p=61, q=53 cho ra n=3233 (CA mặc định trong codebase này).
 * Đặt ngưỡng thấp để tương thích với demo nhưng vẫn cảnh báo giá trị trivial.
 */
#define CSR_MIN_MODULUS ((uint64_t)100)

/* ══════════════════════════════════════════════════════════════════════════
 *  PHẦN I — Quản lý KeyStore
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * csr_init_keystore() — Khởi tạo KeyStore tại đường dẫn cho trước.
 *
 * Tạo thư mục nếu chưa tồn tại. Đặt quyền thư mục là 0700 (chỉ owner).
 * Bật audit log nếu audit_path != NULL.
 *
 * Trả về: CSR_OK nếu thành công.
 */
static inline CSR_Status csr_init_keystore(
    KeyStore   *ks,
    const char *base_dir,
    const char *audit_path   /* NULL để tắt */
) {
    if (!ks || !base_dir) return CSR_ERR_NULLPTR;
    if (strlen(base_dir) >= CSR_PATH_MAX) return CSR_ERR_PATH;

    memset(ks, 0, sizeof(KeyStore));
    strncpy(ks->base_dir, base_dir, CSR_PATH_MAX - 1);
    ks->audit_log = NULL;

    /* Tạo thư mục nếu chưa có */
    struct stat st;
    if (stat(base_dir, &st) != 0) {
        /* Thư mục chưa tồn tại — tạo mới */
        if (MKDIR(base_dir) != 0 && errno != EEXIST) {
            return CSR_ERR_MKDIR;
        }
        /* Đặt quyền thư mục: chỉ owner truy cập được */
#ifndef _WIN32
        chmod(base_dir, 0700);
#endif
    } else if (!S_ISDIR(st.st_mode)) {
        /* Đường dẫn tồn tại nhưng không phải thư mục */
        return CSR_ERR_PATH;
    }

    /* Mở audit log nếu được yêu cầu */
    if (audit_path) {
        ks->audit_log = fopen(audit_path, "a");
        /* Không fatal nếu không mở được — chỉ tắt logging */
    }

    ks->initialized = 1;
    return CSR_OK;
}

/*
 * csr_close_keystore() — Đóng KeyStore và flush audit log.
 */
static inline void csr_close_keystore(KeyStore *ks) {
    if (!ks) return;
    if (ks->audit_log) {
        fclose(ks->audit_log);
        ks->audit_log = NULL;
    }
    ks->initialized = 0;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  PHẦN II — Ghi Audit Log
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * csr_audit() — Ghi một dòng vào audit log kèm timestamp.
 * Format: [YYYY-MM-DD HH:MM:SS] [ACTION] message
 */
static inline void csr_audit(KeyStore *ks, const char *action, const char *msg) {
    if (!ks || !ks->audit_log) return;

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(ks->audit_log, "[%s] [%-12s] %s\n", ts, action, msg ? msg : "");
    fflush(ks->audit_log);
}

/* ══════════════════════════════════════════════════════════════════════════
 *  PHẦN III — Xuất Keypair ra file
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * csr_export_keypair() — Xuất một RSA_Keypair ra file trong KeyStore.
 *
 * Tên file được tạo tự động:
 *   KP_PRIVATE → <base_dir>/<name>_private.key
 *   KP_PUBLIC  → <base_dir>/<name>_public.key
 *
 * Nếu file đã tồn tại, trả về CSR_ERR_EXISTS trừ khi force = 1.
 *
 * Format file:
 *   Dòng 1: "PKI_KEY_V1"                 (magic header)
 *   Dòng 2: "TYPE=PRIVATE" hoặc "TYPE=PUBLIC"
 *   Dòng 3: "N=<decimal>"
 *   Dòng 4: "E=<decimal>"
 *   Dòng 5: "D=<decimal>"                (chỉ có với KP_PRIVATE)
 *   Dòng 6: "---END---"
 *
 * Trả về: CSR_OK nếu thành công.
 */
static inline CSR_Status csr_export_keypair(
    KeyStore          *ks,
    const RSA_Keypair *kp,
    const char        *name,
    CSR_KeyPart        part,
    CSR_Permission     perm,
    int                force   /* 1 = ghi đè nếu file đã tồn tại */
) {
    if (!ks || !kp || !name) return CSR_ERR_NULLPTR;
    if (!ks->initialized)    return CSR_ERR_PERMISSION;
    if (strlen(name) >= CSR_NAME_MAX) return CSR_ERR_OVERFLOW;

    /* Kiểm tra modulus tối thiểu */
    if (kp->n < CSR_MIN_MODULUS) {
        csr_audit(ks, "WARN_EXPORT",
                  "Modulus n quá nhỏ (< CSR_MIN_MODULUS) — chỉ phù hợp để demo");
    }

    /* Kiểm tra private key hợp lệ khi xuất KP_PRIVATE */
    if (part == KP_PRIVATE && kp->d == 0) {
        csr_audit(ks, "ERR_EXPORT", "Private exponent d = 0, keypair chưa được khởi tạo");
        return CSR_ERR_CORRUPT;
    }

    /* Xây dựng đường dẫn file */
    char path[CSR_PATH_MAX];
    int written = snprintf(path, CSR_PATH_MAX, "%s%s%s_%s.key",
                           ks->base_dir, PATH_SEP, name,
                           (part == KP_PRIVATE) ? "private" : "public");
    if (written < 0 || written >= CSR_PATH_MAX) return CSR_ERR_PATH;

    /* Kiểm tra file đã tồn tại */
    if (!force && ACCESS(path, ACCESS_READ) == 0) {
        char buf[CSR_AUDIT_MAX];
        snprintf(buf, CSR_AUDIT_MAX, "File da ton tai, bo qua: %s", path);
        csr_audit(ks, "SKIP_EXPORT", buf);
        return CSR_ERR_EXISTS;
    }

    /* Ghi file */
    FILE *f = fopen(path, "w");
    if (!f) {
        csr_audit(ks, "ERR_EXPORT", "Khong the mo file de ghi");
        return CSR_ERR_IO;
    }

    fprintf(f, "PKI_KEY_V1\n");
    fprintf(f, "TYPE=%s\n", (part == KP_PRIVATE) ? "PRIVATE" : "PUBLIC");
    fprintf(f, "N=%llu\n", (unsigned long long)kp->n);
    fprintf(f, "E=%llu\n", (unsigned long long)kp->e);
    if (part == KP_PRIVATE) {
        fprintf(f, "D=%llu\n", (unsigned long long)kp->d);
    }
    fprintf(f, "---END---\n");
    fclose(f);

    /* Áp dụng quyền truy cập */
    CHMOD(path, (int)perm);

    /* Ghi audit */
    char buf[CSR_AUDIT_MAX];
    snprintf(buf, CSR_AUDIT_MAX, "Xuat thanh cong: %s (perm=%o)", path, (unsigned)perm);
    csr_audit(ks, "EXPORT_OK", buf);

    return CSR_OK;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  PHẦN IV — Nhập Keypair từ file
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * csr_import_keypair() — Đọc RSA_Keypair từ file trong KeyStore.
 *
 * Thực hiện kiểm tra:
 *   - File tồn tại và có thể đọc
 *   - Magic header "PKI_KEY_V1" hợp lệ
 *   - Các trường N, E (và D nếu private) đều có mặt
 *   - Modulus n >= CSR_MIN_MODULUS
 *
 * Trả về: CSR_OK nếu thành công, ghi kết quả vào *kp_out.
 */
static inline CSR_Status csr_import_keypair(
    KeyStore    *ks,
    RSA_Keypair *kp_out,
    const char  *name,
    CSR_KeyPart  part
) {
    if (!ks || !kp_out || !name) return CSR_ERR_NULLPTR;
    if (!ks->initialized)        return CSR_ERR_PERMISSION;
    if (strlen(name) >= CSR_NAME_MAX) return CSR_ERR_OVERFLOW;

    /* Xây dựng đường dẫn */
    char path[CSR_PATH_MAX];
    int written = snprintf(path, CSR_PATH_MAX, "%s%s%s_%s.key",
                           ks->base_dir, PATH_SEP, name,
                           (part == KP_PRIVATE) ? "private" : "public");
    if (written < 0 || written >= CSR_PATH_MAX) return CSR_ERR_PATH;

    /* Kiểm tra file tồn tại */
    if (ACCESS(path, ACCESS_READ) != 0) {
        csr_audit(ks, "ERR_IMPORT", "File khoa khong ton tai");
        return CSR_ERR_NOT_FOUND;
    }

    /* Với private key: kiểm tra quyền không quá thoáng */
#ifndef _WIN32
    if (part == KP_PRIVATE) {
        struct stat st;
        if (stat(path, &st) == 0) {
            if ((st.st_mode & 0777) & 0044) {
                /* File private key mà group/others có thể đọc — cảnh báo */
                csr_audit(ks, "WARN_IMPORT",
                          "Private key co the bi doc boi group/others (perm qua thoang)");
            }
        }
    }
#endif

    FILE *f = fopen(path, "r");
    if (!f) {
        csr_audit(ks, "ERR_IMPORT", "Khong the mo file de doc");
        return CSR_ERR_IO;
    }

    /* Đọc và kiểm tra magic header */
    char magic[32] = {0};
    if (!fgets(magic, sizeof(magic), f)) { fclose(f); return CSR_ERR_CORRUPT; }
    magic[strcspn(magic, "\r\n")] = '\0';
    if (strcmp(magic, "PKI_KEY_V1") != 0) {
        fclose(f);
        csr_audit(ks, "ERR_IMPORT", "Magic header sai — file khong dung dinh dang");
        return CSR_ERR_CORRUPT;
    }

    /* Khởi tạo output */
    memset(kp_out, 0, sizeof(RSA_Keypair));

    int got_n = 0, got_e = 0, got_d = 0;
    char line[128];

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strcmp(line, "---END---") == 0) break;

        unsigned long long val = 0;
        if (sscanf(line, "N=%llu", &val) == 1) { kp_out->n = (uint64_t)val; got_n = 1; }
        else if (sscanf(line, "E=%llu", &val) == 1) { kp_out->e = (uint64_t)val; got_e = 1; }
        else if (sscanf(line, "D=%llu", &val) == 1) { kp_out->d = (uint64_t)val; got_d = 1; }
        /* Các dòng khác (TYPE=...) bỏ qua */
    }
    fclose(f);

    /* Kiểm tra đủ trường */
    if (!got_n || !got_e) {
        csr_audit(ks, "ERR_IMPORT", "File thieu truong N hoac E");
        return CSR_ERR_CORRUPT;
    }
    if (part == KP_PRIVATE && !got_d) {
        csr_audit(ks, "ERR_IMPORT", "Yeu cau private key nhung khong co truong D");
        return CSR_ERR_CORRUPT;
    }

    /* Kiểm tra modulus */
    if (kp_out->n < CSR_MIN_MODULUS) {
        csr_audit(ks, "WARN_IMPORT", "Modulus n rat nho — chi dung cho demo");
    }

    /* Ghi audit */
    char buf[CSR_AUDIT_MAX];
    snprintf(buf, CSR_AUDIT_MAX, "Doc thanh cong: %s (n=%llu)",
             path, (unsigned long long)kp_out->n);
    csr_audit(ks, "IMPORT_OK", buf);

    return CSR_OK;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  PHẦN V — Tiện ích bổ sung
 * ══════════════════════════════════════════════════════════════════════════ */

/*
 * csr_key_exists() — Kiểm tra một file khóa đã tồn tại trong KeyStore.
 *
 * Trả về: 1 nếu tồn tại, 0 nếu không.
 */
static inline int csr_key_exists(
    const KeyStore *ks,
    const char     *name,
    CSR_KeyPart     part
) {
    if (!ks || !name || !ks->initialized) return 0;

    char path[CSR_PATH_MAX];
    int written = snprintf(path, CSR_PATH_MAX, "%s%s%s_%s.key",
                           ks->base_dir, PATH_SEP, name,
                           (part == KP_PRIVATE) ? "private" : "public");
    if (written < 0 || written >= CSR_PATH_MAX) return 0;

    return (ACCESS(path, ACCESS_READ) == 0) ? 1 : 0;
}

/*
 * csr_delete_key() — Xóa một file khóa khỏi KeyStore.
 *
 * Dùng để thu hồi hoặc rotate key. Ghi audit trước khi xóa.
 * Trả về: CSR_OK nếu xóa được, CSR_ERR_NOT_FOUND nếu không tồn tại.
 */
static inline CSR_Status csr_delete_key(
    KeyStore   *ks,
    const char *name,
    CSR_KeyPart part
) {
    if (!ks || !name) return CSR_ERR_NULLPTR;
    if (!ks->initialized) return CSR_ERR_PERMISSION;

    char path[CSR_PATH_MAX];
    int written = snprintf(path, CSR_PATH_MAX, "%s%s%s_%s.key",
                           ks->base_dir, PATH_SEP, name,
                           (part == KP_PRIVATE) ? "private" : "public");
    if (written < 0 || written >= CSR_PATH_MAX) return CSR_ERR_PATH;

    if (ACCESS(path, ACCESS_READ) != 0) return CSR_ERR_NOT_FOUND;

    char buf[CSR_AUDIT_MAX];
    snprintf(buf, CSR_AUDIT_MAX, "XOA file khoa: %s", path);
    csr_audit(ks, "DELETE_KEY", buf);

    if (remove(path) != 0) {
        csr_audit(ks, "ERR_DELETE", "Khong the xoa file");
        return CSR_ERR_IO;
    }

    return CSR_OK;
}

/*
 * csr_set_permission() — Thay đổi quyền của một file khóa đã tồn tại.
 *
 * Ví dụ: sau khi cấp phát xong, "đóng băng" public key thành PERM_READ_ONLY.
 */
static inline CSR_Status csr_set_permission(
    KeyStore      *ks,
    const char    *name,
    CSR_KeyPart    part,
    CSR_Permission perm
) {
    if (!ks || !name) return CSR_ERR_NULLPTR;
    if (!ks->initialized) return CSR_ERR_PERMISSION;

    char path[CSR_PATH_MAX];
    int written = snprintf(path, CSR_PATH_MAX, "%s%s%s_%s.key",
                           ks->base_dir, PATH_SEP, name,
                           (part == KP_PRIVATE) ? "private" : "public");
    if (written < 0 || written >= CSR_PATH_MAX) return CSR_ERR_PATH;

    if (ACCESS(path, ACCESS_READ) != 0) return CSR_ERR_NOT_FOUND;

    if (CHMOD(path, (int)perm) != 0) {
        csr_audit(ks, "ERR_CHMOD", "Khong the doi quyen file");
        return CSR_ERR_PERMISSION;
    }

    char buf[CSR_AUDIT_MAX];
    snprintf(buf, CSR_AUDIT_MAX, "Doi quyen %s -> %o", path, (unsigned)perm);
    csr_audit(ks, "CHMOD_OK", buf);

    return CSR_OK;
}

/*
 * csr_strerror() — Chuyển mã lỗi thành chuỗi mô tả tiếng Việt.
 */
static inline const char *csr_strerror(CSR_Status status) {
    switch (status) {
        case CSR_OK:             return "Thanh cong";
        case CSR_ERR_NULLPTR:    return "Con tro NULL khong hop le";
        case CSR_ERR_PATH:       return "Duong dan khong hop le hoac qua dai";
        case CSR_ERR_MKDIR:      return "Khong the tao thu muc";
        case CSR_ERR_EXISTS:     return "File da ton tai (dung force=1 de ghi de)";
        case CSR_ERR_NOT_FOUND:  return "File khoa khong tim thay";
        case CSR_ERR_PERMISSION: return "Khong du quyen truy cap";
        case CSR_ERR_IO:         return "Loi doc/ghi file";
        case CSR_ERR_CORRUPT:    return "File khoa bi hong hoac sai dinh dang";
        case CSR_ERR_OVERFLOW:   return "Ten qua dai, buffer overflow";
        case CSR_ERR_KEYSIZE:    return "Modulus n qua nho";
        default:                 return "Loi khong xac dinh";
    }
}

/*
 * csr_check_rc() — Macro kiểm tra mã trả về và in thông báo lỗi nếu thất bại.
 * Dùng trong hàm có kiểu trả về int/void để tránh lặp code kiểm tra lỗi.
 *
 * Ví dụ:
 *   CSR_CHECK(csr_init_keystore(&ks, "keys", "audit.log"), "Khoi tao keystore");
 */
#define CSR_CHECK(expr, label)                                              \
    do {                                                                    \
        CSR_Status _s = (expr);                                             \
        if (_s != CSR_OK) {                                                 \
            fprintf(stderr, "[CSR][LOI] %s: %s\n", (label), csr_strerror(_s)); \
        }                                                                   \
    } while (0)

/*
 * CSR_CHECK_FATAL() — Như CSR_CHECK nhưng thoát chương trình khi thất bại.
 * Dùng cho các thao tác bắt buộc phải thành công (khởi tạo CA, v.v.).
 */
#define CSR_CHECK_FATAL(expr, label)                                        \
    do {                                                                    \
        CSR_Status _s = (expr);                                             \
        if (_s != CSR_OK) {                                                 \
            fprintf(stderr, "[CSR][FATAL] %s: %s\n", (label), csr_strerror(_s)); \
            exit(EXIT_FAILURE);                                             \
        }                                                                   \
    } while (0)

#endif /* CSR_H */
