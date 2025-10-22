#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <jansson.h>
#include <termios.h>
#include <unistd.h>

#define DB_FILE "passwords.db"
#define CONFIG_FILE "config.dat"
#define SALT_SIZE 16
#define IV_SIZE 16
#define KEY_SIZE 32 // AES-256
#define MAX_ATTEMPTS 5

// --- Deklarasi Fungsi (Prototypes) ---
void clear_screen();
void get_password(const char *prompt, char *password, size_t size);
int generate_key(const char *password, const unsigned char *salt, unsigned char *key, unsigned char *iv);
int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext);
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext);
void save_db(json_t *root, const unsigned char *key, const unsigned char *iv);
json_t *load_db(const unsigned char *key, const unsigned char *iv);
int verify_master_password(json_t *root);
int authenticate_user(const char *current_master_password);

void list_account_names(json_t *root);
void display_and_select_account(json_t *root);
void add_account(json_t *root);
void edit_account(json_t *root);
void delete_account(json_t *root, const char *master_password);

void change_master_password(json_t *root, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt);
void reset_database(json_t **root_ptr, const char *master_password);
void factory_reset(const char *master_password);
void settings_menu(json_t **root_ptr, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt);
void main_menu(json_t *root, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt);

// Fungsi untuk membersihkan layar terminal
void clear_screen() {
    // Perintah "clear" untuk sistem Unix-like (Linux, macOS)
    system("clear");
}

// Fungsi untuk menyembunyikan input password
void get_password(const char *prompt, char *password, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(password, size, stdin);
    password[strcspn(password, "\n")] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

// Fungsi untuk menghasilkan kunci dari password utama menggunakan PBKDF2
int generate_key(const char *password, const unsigned char *salt, unsigned char *key, unsigned char *iv) {
    unsigned char derived_key[KEY_SIZE + IV_SIZE];
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, SALT_SIZE, 10000, EVP_sha256(), KEY_SIZE + IV_SIZE, derived_key)) {
        fprintf(stderr, "Error: Gagal menghasilkan kunci dari password.\n");
        return 0;
    }
    memcpy(key, derived_key, KEY_SIZE);
    memcpy(iv, derived_key + KEY_SIZE, IV_SIZE);
    return 1;
}

// Fungsi untuk mengenkripsi data
int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Fungsi untuk mendekripsi data
int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) { EVP_CIPHER_CTX_free(ctx); return -1; }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Fungsi untuk menyimpan data terenkripsi ke file
void save_db(json_t *root, const unsigned char *key, const unsigned char *iv) {
    char *json_str = json_dumps(root, JSON_INDENT(4));
    if (!json_str) { fprintf(stderr, "Error: Gagal mengubah JSON ke string.\n"); exit(1); }
    int plaintext_len = strlen(json_str);
    unsigned char *ciphertext = malloc(plaintext_len + AES_BLOCK_SIZE);
    if (!ciphertext) { fprintf(stderr, "Error: Gagal mengalokasikan memori.\n"); free(json_str); exit(1); }
    int ciphertext_len = encrypt_data((unsigned char *)json_str, plaintext_len, key, iv, ciphertext);
    if (ciphertext_len < 0) { fprintf(stderr, "Error: Enkripsi gagal.\n"); free(json_str); free(ciphertext); exit(1); }
    FILE *fp = fopen(DB_FILE, "wb");
    if (!fp) { fprintf(stderr, "Error: Tidak dapat membuka file database.\n"); free(json_str); free(ciphertext); exit(1); }
    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);
    free(json_str);
    free(ciphertext);
}

// Fungsi untuk memuat dan mendekripsi data dari file
json_t *load_db(const unsigned char *key, const unsigned char *iv) {
    FILE *fp = fopen(DB_FILE, "rb");
    if (!fp) {
        json_t *root = json_object();
        json_object_set_new(root, "verification_text", json_string("check_ok"));
        json_object_set_new(root, "accounts", json_array());
        save_db(root, key, iv);
        return root;
    }
    fseek(fp, 0, SEEK_END);
    long ciphertext_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) { fprintf(stderr, "Error: Gagal alokasi memori.\n"); fclose(fp); exit(1); }
    fread(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);
    unsigned char *plaintext = malloc(ciphertext_len + 1);
    if (!plaintext) { fprintf(stderr, "Error: Gagal alokasi memori.\n"); free(ciphertext); exit(1); }
    int plaintext_len = decrypt_data(ciphertext, ciphertext_len, key, iv, plaintext);
    if (plaintext_len < 0) { free(ciphertext); free(plaintext); return NULL; }
    plaintext[plaintext_len] = '\0';
    free(ciphertext);
    json_error_t error;
    json_t *root = json_loads((char *)plaintext, 0, &error);
    free(plaintext);
    if (!root) { fprintf(stderr, "Error parsing JSON: %s\n", error.text); exit(1); }
    return root;
}

// Fungsi untuk memeriksa kebenaran password utama
int verify_master_password(json_t *root) {
    json_t *verification_text_json = json_object_get(root, "verification_text");
    if (!json_is_string(verification_text_json)) return 0;
    return strcmp(json_string_value(verification_text_json), "check_ok") == 0;
}

// Fungsi otentikasi pengguna dengan batas percobaan
int authenticate_user(const char *current_master_password) {
    clear_screen();
    printf("Aksi ini memerlukan keamanan tinggi.\n");
    int attempts = 0;
    char entered_password[256];
    while (attempts < MAX_ATTEMPTS) {
        get_password("Masukkan password utama aplikasi: ", entered_password, sizeof(entered_password));
        if (strcmp(current_master_password, entered_password) == 0) {
            return 1; // Berhasil
        } else {
            attempts++;
            printf("Password salah! Sisa percobaan: %d\n", MAX_ATTEMPTS - attempts);
        }
    }
    fprintf(stderr, "Batas percobaan terlampaui. Keluar dari program.\n");
    exit(1);
}

// Fungsi untuk menampilkan nama-nama akun
void list_account_names(json_t *root) {
    json_t *accounts = json_object_get(root, "accounts");
    printf("\n--- Daftar Akun Tersimpan ---\n");
    if (json_array_size(accounts) == 0) {
        printf("Tidak ada akun yang tersimpan.\n");
    } else {
        size_t index;
        json_t *value;
        json_array_foreach(accounts, index, value) {
            const char *name = json_string_value(json_object_get(value, "name"));
            printf("%zu. %s\n", index + 1, name);
        }
    }
    printf("---------------------------\n");
}

// Fungsi untuk menampilkan daftar dan detail akun
void display_and_select_account(json_t *root) {
    clear_screen();
    list_account_names(root);
    json_t *accounts = json_object_get(root, "accounts");
    size_t count = json_array_size(accounts);

    if (count == 0) {
        printf("\nTekan Enter untuk kembali...");
        getchar();
        return;
    }

    printf("Masukkan nomor urutan akun untuk melihat detail (atau 0 untuk kembali): ");
    int index;
    if (scanf("%d", &index) != 1) {
        fprintf(stderr, "Error: Input tidak valid.\n");
        exit(1);
    }
    while (getchar() != '\n'); // Membersihkan buffer

    if (index == 0) return;

    if (index < 1 || index > count) {
        printf("Nomor urutan tidak valid.\n");
    } else {
        json_t *account = json_array_get(accounts, index - 1);
        const char *name = json_string_value(json_object_get(account, "name"));
        const char *desc = json_string_value(json_object_get(account, "description"));
        const char *pass = json_string_value(json_object_get(account, "password"));

        printf("\n--- Detail Akun #%d ---\n", index);
        printf("Nama Akun  : %s\n", name);
        printf("Deskripsi  : %s\n", desc);
        printf("Password   : %s\n", pass);
        printf("----------------------\n");
    }
    printf("\nTekan Enter untuk kembali ke menu utama...");
    getchar();
}

// Fungsi untuk menambah akun baru
void add_account(json_t *root) {
    clear_screen();
    char name[256], description[512], password[256];
    printf("--- Tambah Akun Baru ---\n");
    printf("Masukkan Nama Akun: ");
    fgets(name, sizeof(name), stdin); name[strcspn(name, "\n")] = 0;
    printf("Masukkan Deskripsi: ");
    fgets(description, sizeof(description), stdin); description[strcspn(description, "\n")] = 0;
    get_password("Masukkan Password Akun: ", password, sizeof(password));
    json_t *new_account = json_object();
    json_object_set_new(new_account, "name", json_string(name));
    json_object_set_new(new_account, "description", json_string(description));
    json_object_set_new(new_account, "password", json_string(password));
    json_array_append_new(json_object_get(root, "accounts"), new_account);
    printf("Akun berhasil ditambahkan!\n");
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

// Fungsi untuk mengubah akun
void edit_account(json_t *root) {
    clear_screen();
    list_account_names(root);
    json_t *accounts = json_object_get(root, "accounts");
    size_t count = json_array_size(accounts);
    if (count == 0) {
        printf("\nTekan Enter untuk kembali...");
        getchar();
        return;
    }
    printf("Masukkan nomor urutan akun yang ingin diubah: ");
    int index;
    if (scanf("%d", &index) != 1 || index < 1 || index > count) { fprintf(stderr, "Error: Input tidak valid.\n"); exit(1); }
    while (getchar() != '\n');
    json_t *account = json_array_get(accounts, index - 1);
    printf("\nPilih data yang ingin diubah:\n1. Nama Akun\n2. Deskripsi\n3. Password\nPilihan Anda: ");
    int choice;
    if (scanf("%d", &choice) != 1) { fprintf(stderr, "Error: Input tidak valid.\n"); exit(1); }
    while (getchar() != '\n');
    char buffer[512];
    switch (choice) {
        case 1:
            printf("Masukkan Nama Akun baru: ");
            fgets(buffer, sizeof(buffer), stdin); buffer[strcspn(buffer, "\n")] = 0;
            json_object_set_new(account, "name", json_string(buffer));
            break;
        case 2:
            printf("Masukkan Deskripsi baru: ");
            fgets(buffer, sizeof(buffer), stdin); buffer[strcspn(buffer, "\n")] = 0;
            json_object_set_new(account, "description", json_string(buffer));
            break;
        case 3:
            get_password("Masukkan Password baru: ", buffer, sizeof(buffer));
            json_object_set_new(account, "password", json_string(buffer));
            break;
        default: printf("Pilihan tidak valid.\n"); return;
    }
    printf("Akun berhasil diubah!\n");
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

// Fungsi untuk menghapus akun
void delete_account(json_t *root, const char *master_password) {
    clear_screen();
    list_account_names(root);
    json_t *accounts = json_object_get(root, "accounts");
    size_t count = json_array_size(accounts);
    if (count == 0) {
        printf("\nTekan Enter untuk kembali...");
        getchar();
        return;
    }
    printf("Masukkan nomor urutan akun yang ingin dihapus: ");
    int index;
    if (scanf("%d", &index) != 1 || index < 1 || index > count) { fprintf(stderr, "Error: Input tidak valid.\n"); exit(1); }
    while (getchar() != '\n');
    printf("Apakah Anda yakin ingin menghapus akun ini? (y/n): ");
    char confirm = getchar();
    while (getchar() != '\n');
    if (confirm != 'y' && confirm != 'Y') { printf("Penghapusan dibatalkan.\n"); return; }
    if (authenticate_user(master_password)) {
        json_array_remove(accounts, index - 1);
        printf("Akun berhasil dihapus!\n");
    }
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

// --- FUNGSI PENGATURAN ---
void change_master_password(json_t *root, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt) {
    if (!authenticate_user(master_password)) return;
    
    char new_pass[256], confirm_pass[256];
    get_password("Masukkan Password Utama BARU: ", new_pass, sizeof(new_pass));
    get_password("Konfirmasi Password Utama BARU: ", confirm_pass, sizeof(confirm_pass));

    if (strcmp(new_pass, confirm_pass) != 0) {
        printf("Password baru tidak cocok. Perubahan dibatalkan.\n");
    } else {
        strcpy(master_password, new_pass);
        if (!generate_key(master_password, salt, key, iv)) {
            fprintf(stderr, "Gagal menghasilkan kunci baru. Aplikasi akan keluar.\n");
            exit(1);
        }
        printf("Password utama berhasil diubah! Database akan dienkripsi ulang.\n");
    }
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

void reset_database(json_t **root_ptr, const char *master_password) {
    if (!authenticate_user(master_password)) return;

    printf("PERINGATAN: Aksi ini akan menghapus SEMUA akun yang tersimpan.\n");
    printf("Apakah Anda benar-benar yakin? (ketik 'YA' untuk konfirmasi): ");
    char confirmation[10];
    fgets(confirmation, sizeof(confirmation), stdin);
    confirmation[strcspn(confirmation, "\n")] = 0;
    
    if (strcmp(confirmation, "YA") == 0) {
        json_decref(*root_ptr); // Hapus data JSON lama
        *root_ptr = json_object(); // Buat objek JSON baru
        json_object_set_new(*root_ptr, "verification_text", json_string("check_ok"));
        json_object_set_new(*root_ptr, "accounts", json_array());
        printf("Semua data akun telah direset.\n");
    } else {
        printf("Reset dibatalkan.\n");
    }
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

void factory_reset(const char *master_password) {
    if (!authenticate_user(master_password)) return;

    printf("!!!PERINGATAN KERAS!!!\n");
    printf("Aksi ini akan MENGHAPUS seluruh database dan konfigurasi.\n");
    printf("Aplikasi akan kembali ke kondisi awal dan Anda akan kehilangan semua data.\n");
    printf("Apakah Anda 100%% yakin? (ketik 'HAPUS SEMUANYA' untuk konfirmasi): ");
    char confirmation[20];
    fgets(confirmation, sizeof(confirmation), stdin);
    confirmation[strcspn(confirmation, "\n")] = 0;

    if (strcmp(confirmation, "HAPUS SEMUANYA") == 0) {
        remove(DB_FILE);
        remove(CONFIG_FILE);
        printf("Factory reset berhasil. Aplikasi akan ditutup.\n");
        printf("Jalankan kembali aplikasi untuk memulai dari awal.\n");
        exit(0);
    } else {
        printf("Factory reset dibatalkan.\n");
    }
    printf("\nTekan Enter untuk kembali...");
    getchar();
}

void settings_menu(json_t **root_ptr, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt) {
    int choice = 0;
    while(choice != 4) {
        clear_screen();
        printf("\n--- PENGATURAN ---\n");
        printf("1. Ganti Password Utama\n");
        printf("2. Reset Isi Database (Hapus Semua Akun)\n");
        printf("3. Factory Reset (Hapus Semua Data & Konfigurasi)\n");
        printf("4. Kembali ke Menu Utama\n");
        printf("------------------\n");
        printf("Pilihan Anda: ");

        if (scanf("%d", &choice) != 1) { fprintf(stderr, "Error: Input tidak valid.\n"); exit(1); }
        while (getchar() != '\n');

        switch (choice) {
            case 1:
                change_master_password(*root_ptr, key, iv, master_password, salt);
                save_db(*root_ptr, key, iv); // Langsung simpan setelah ganti kunci
                break;
            case 2:
                reset_database(root_ptr, master_password);
                save_db(*root_ptr, key, iv); // Simpan database yang sudah kosong
                break;
            case 3:
                factory_reset(master_password);
                break; // factory_reset akan keluar jika berhasil
            case 4:
                // Hanya keluar dari loop untuk kembali
                break;
            default:
                printf("Pilihan tidak valid. Tekan Enter untuk mencoba lagi...");
                getchar();
        }
    }
}

// Fungsi untuk menu utama
void main_menu(json_t *root, unsigned char *key, unsigned char *iv, char *master_password, const unsigned char *salt) {
    int choice = 0;
    while (choice != 6) {
        clear_screen();
        printf("\n--- PENGELOLA KATA SANDI ---\n");
        printf("1. Tambah Akun\n");
        printf("2. Ganti Akun\n");
        printf("3. Hapus Akun\n");
        printf("4. Tampilkan Daftar & Detail Akun\n");
        printf("5. Pengaturan\n");
        printf("6. Keluar Aplikasi\n");
        printf("----------------------------\n");
        printf("Pilihan Anda: ");

        if (scanf("%d", &choice) != 1) { fprintf(stderr, "Error: Input tidak valid.\n"); exit(1); }
        while (getchar() != '\n'); 

        switch (choice) {
            case 1: add_account(root); save_db(root, key, iv); break;
            case 2: edit_account(root); save_db(root, key, iv); break;
            case 3: delete_account(root, master_password); save_db(root, key, iv); break;
            case 4: display_and_select_account(root); break;
            case 5: settings_menu(&root, key, iv, master_password, salt); break;
            case 6: {
                clear_screen();
                char confirm_exit;
                printf("Apakah Anda yakin ingin keluar? (y/n): ");
                scanf(" %c", &confirm_exit);
                while (getchar() != '\n'); 
                if (confirm_exit == 'y' || confirm_exit == 'Y') {
                    // Biarkan loop berakhir
                } else {
                    choice = 0; // Reset pilihan agar loop berlanjut
                }
                break;
            }
            default: 
                printf("Pilihan tidak valid. Tekan Enter untuk mencoba lagi...");
                getchar();
        }
    }
}

int main() {
    clear_screen();
    char master_password[256];
    unsigned char salt[SALT_SIZE];
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];

    FILE *fp_config = fopen(CONFIG_FILE, "rb");
    if (!fp_config) {
        printf("\rSelamat datang di Pengelola Kata Sandi!\n");
        printf("Karena ini pertama kali, silakan buat password utama untuk aplikasi.\n\n");
        get_password("Password Utama Baru: ", master_password, sizeof(master_password));
        char confirm_password[256];
        get_password("Konfirmasi Password: ", confirm_password, sizeof(confirm_password));
        if (strcmp(master_password, confirm_password) != 0) { fprintf(stderr, "Password tidak cocok.\n"); return 1; }
        if (!RAND_bytes(salt, sizeof(salt))) { fprintf(stderr, "Error: Gagal menghasilkan salt.\n"); return 1; }
        fp_config = fopen(CONFIG_FILE, "wb");
        if (!fp_config) { fprintf(stderr, "Error: Tidak dapat membuat file konfigurasi.\n"); return 1; }
        fwrite(salt, 1, sizeof(salt), fp_config);
        fclose(fp_config);
        printf("Password utama berhasil dibuat!\n");
        printf("Tekan Enter untuk melanjutkan ke login...");
        getchar();

    } else {
        fread(salt, 1, sizeof(salt), fp_config);
        fclose(fp_config);
    }
    
    clear_screen();
    printf("\n--- Selamat Datang Kembali ---\n");
    int attempts = 0;
    json_t *db = NULL;
    while (attempts < MAX_ATTEMPTS) {
        get_password("Masukkan Password Aplikasi Utama: ", master_password, sizeof(master_password));
        if (!generate_key(master_password, salt, key, iv)) exit(1);
        db = load_db(key, iv);
        if (db && verify_master_password(db)) {
            printf("Login berhasil!\n");
            printf("Tekan Enter untuk masuk ke menu utama...");
            getchar();
            break;
        } else {
            if (db) json_decref(db);
            db = NULL;
            attempts++;
            printf("Password salah! Sisa percobaan: %d\n", MAX_ATTEMPTS - attempts);
        }
    }

    if (!db) {
        fprintf(stderr, "Batas percobaan terlampaui. Keluar dari program.\n");
        return 1;
    }
    
    main_menu(db, key, iv, master_password, salt);
    
    clear_screen();
    printf("Terima kasih telah menggunakan aplikasi ini.\n");

    json_decref(db);
    return 0;
}
