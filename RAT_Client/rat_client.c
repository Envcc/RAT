#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

#define AES_KEY "0123456789abcdef"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

// Anti-Debugging
void anti_debug() {
    __asm__ __volatile__ (
        "xor %eax, %eax\n\t"
        "mov $0x1, %eax\n\t"
        "int $0x80\n\t"
        "cmp %eax, $0x0\n\t"
        "jne _debugged\n\t"
        "_not_debugged:\n\t"
        "jmp _end\n\t"
        "_debugged:\n\t"
        "mov $0x1, %eax\n\t"
        "int $0x80\n\t"
        "_end:\n\t"
    );
    if (getppid() != 1) exit(1);
}

// AES Encryption/Decryption
void aes_encrypt(unsigned char *plaintext, unsigned char *key, unsigned char *ciphertext) {
    AES_KEY enc_key;
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(key, 128, &enc_key);
    AES_cfb128_encrypt(plaintext, ciphertext, strlen((char *)plaintext), &enc_key, iv, NULL, AES_ENCRYPT);
}

void aes_decrypt(unsigned char *ciphertext, unsigned char *key, unsigned char *plaintext) {
    AES_KEY dec_key;
    unsigned char iv[AES_BLOCK_SIZE];
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_cfb128_encrypt(ciphertext, plaintext, strlen((char *)ciphertext), &dec_key, iv, NULL, AES_DECRYPT);
}

// String Encryption and Decryption at Runtime
const char* enc_str = "\x53\x61\x6D\x70\x6C\x65"; // "Sample" XOR-ed with 0x20
const char k = 0x20;

char* decrypt_string(const char* enc_str) {
    size_t len = strlen(enc_str);
    char* dec_str = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        dec_str[i] = enc_str[i] ^ k;
    }
    dec_str[len] = '\0';
    return dec_str;
}

// Task Execution with Control Flow Obfuscation
void fn1(const char* tsk) {
    unsigned char k[16] = AES_KEY;
    unsigned char buf[64];
    int state = 0;

    if (strcmp(tsk, "encrypt") == 0) {
        state = 1;
    } else if (strcmp(tsk, "decrypt") == 0) {
        state = 2;
    } else {
        state = 3;
    }

    while (1) {
        switch (state) {
            case 1:
                {
                    unsigned char pt[64] = "Sensitive data";
                    unsigned char ct[64];
                    aes_encrypt(pt, k, ct);
                    printf("Encrypted: %s\n", ct);
                    state = 4; // Move to a different state after this
                    break;
                }
            case 2:
                {
                    unsigned char ct[64] = "EncryptedData";
                    unsigned char pt[64];
                    aes_decrypt(ct, k, pt);
                    printf("Decrypted: %s\n", pt);
                    state = 4; // Move to a different state after this
                    break;
                }
            case 3:
                {
                    printf("Unknown task\n");
                    state = 4; // Move to a different state after this
                    break;
                }
            case 4:
                {
                    // Exit point, obfuscates the real exit
                    return;
                }
            default:
                state = 4; // Default to exit state
                break;
        }
    }
}

// Server Communication
void comm_srv(const char* msg) {
    int s;
    struct sockaddr_in addr;
    char buf[1024];
    int br;

    s = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Connection failed\n");
        return;
    }

    write(s, msg, strlen(msg));
    br = read(s, buf, sizeof(buf) - 1);
    if (br > 0) {
        buf[br] = '\0';
        printf("Received: %s\n", buf);
    }

    close(s);
}

int main(int argc, char *argv[]) {
    anti_debug();

    if (argc > 1) {
        fn1(argv[1]);
        comm_srv(argv[1]);
    } else {
        printf("No task provided\n");
    }
    return 0;
}
