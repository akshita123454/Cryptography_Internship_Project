import socket
import threading
import os
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()

# ------------- ENCRYPTION + HMAC INTEGRITY CHECK -------------

def derive_keys(password: bytes, salt: bytes) -> tuple:
    """Derive AES key and HMAC key using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,  # 32 bytes for AES, 32 bytes for HMAC
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password)
    return key[:32], key[32:]

def encrypt(data: bytes, password: bytes) -> bytes:
    """Encrypts and authenticates the data using AES-CBC + HMAC."""
    salt = os.urandom(16)
    iv = os.urandom(16)
    enc_key, mac_key = derive_keys(password, salt)

    # Pad data manually (PKCS7)
    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)

    # AES encryption
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # HMAC integrity tag
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    tag = h.finalize()

    return salt + iv + tag + ciphertext

def decrypt(enc_data: bytes, password: bytes) -> bytes:
    """Decrypts and verifies the data using AES-CBC + HMAC."""
    salt = enc_data[:16]
    iv = enc_data[16:32]
    tag = enc_data[32:64]
    ciphertext = enc_data[64:]

    enc_key, mac_key = derive_keys(password, salt)

    # Verify HMAC
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    h.verify(tag)  # Raises exception if verification fails

    # AES decryption
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    padding_len = padded_data[-1]
    return padded_data[:-padding_len]

# ------------- PEER-TO-PEER SOCKET COMMUNICATION -------------

def send_message(sock, password, target_port):
    msg = input("Enter message: ").encode()
    encrypted = encrypt(msg, password)
    sock.sendto(b"msg" + encrypted, ("localhost", target_port))
    print("[SENT] Encrypted message sent.")

def send_file(sock, password, target_port):
    filepath = input("Enter file path: ").strip()
    if not os.path.exists(filepath):
        print("[ERROR] File not found.")
        return
    with open(filepath, "rb") as f:
        data = f.read()
    encrypted = encrypt(data, password)
    sock.sendto(b"file" + encrypted, ("localhost", target_port))
    print(f"[SENT] File '{filepath}' sent.")

def handle_peer(sock, password):
    while True:
        try:
            data, addr = sock.recvfrom(65536)
            if data.startswith(b"msg"):
                try:
                    decrypted = decrypt(data[3:], password)
                    print(f"[MESSAGE from {addr}] {decrypted.decode()}")
                except Exception as e:
                    print(f"[ERROR] Message integrity failed: {e}")
            elif data.startswith(b"file"):
                try:
                    decrypted = decrypt(data[4:], password)
                    filename = f"received_file_from_{addr[1]}.bin"
                    with open(filename, "wb") as f:
                        f.write(decrypted)
                    print(f"[RECEIVED] File saved as '{filename}'")
                except Exception as e:
                    print(f"[ERROR] File integrity failed: {e}")
        except Exception as e:
            print(f"[ERROR] Connection error: {e}")

def main():
    password = input("Enter shared password: ").encode()

    my_port = int(input("Enter your port: "))
    peer_port = int(input("Enter peer's port: "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("localhost", my_port))
    print(f"[LISTENING] on port {my_port}...")

    # Thread to receive messages
    threading.Thread(target=handle_peer, args=(sock, password), daemon=True).start()

    # Command loop
    while True:
        cmd = input("\nType msg / file / exit: ").strip().lower()
        if cmd == "msg":
            send_message(sock, password, peer_port)
        elif cmd == "file":
            send_file(sock, password, peer_port)
        elif cmd == "exit":
            print("[INFO] Exiting.")
            break
        else:
            print("[ERROR] Invalid command.")

if __name__ == "__main__":
    main()
