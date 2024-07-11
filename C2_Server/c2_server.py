import socket
import struct
import select
from Crypto.Cipher import AES
import base64

def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt(raw, key):
    raw = pad(raw)
    iv = base64.b64decode('this is an IV456')
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode('utf-8'))).decode('utf-8')

def decrypt(enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CFB, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

def create_icmp_socket():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        return sock
    except Exception as e:
        print(f"Socket creation failed: {e}")
        return None

def receive_icmp(sock):
    while True:
        ready = select.select([sock], [], [], 1)
        if ready[0]:
            packet, addr = sock.recvfrom(1024)
            icmp_header = packet[20:28]
            type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
            data = packet[28:]
            if type == 8:  # Echo request
                return data, addr

def send_icmp(sock, message, addr):
    icmp_type = 0  # Echo reply
    code = 0
    checksum = 0
    p_id = 1
    sequence = 1
    header = struct.pack('bbHHh', icmp_type, code, checksum, p_id, sequence)
    packet = header + message
    checksum = calc_checksum(packet)
    packet = struct.pack('bbHHh', icmp_type, code, checksum, p_id, sequence) + message
    sock.sendto(packet, addr)

def calc_checksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    checksum = 0
    for i in range(0, len(packet), 2):
        part = packet[i] + (packet[i+1] << 8)
        checksum += part
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += (checksum >> 16)
    return ~checksum & 0xffff

def main():
    key = "0123456789abcdef"
    sock = create_icmp_socket()
    if sock is None:
        return

    while True:
        data, addr = receive_icmp(sock)
        if data:
            try:
                decrypted_message = decrypt(data.decode('utf-8'), key)
                print(f"Received from {addr}: {decrypted_message}")
                response_message = "Command received"
                encrypted_response = encrypt(response_message, key).encode('utf-8')
                send_icmp(sock, encrypted_response, addr)
            except Exception as e:
                print(f"Decryption/Encryption error: {e}")

if __name__ == '__main__':
    main()
