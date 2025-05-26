import socket
import threading
import os


def simple_hash(data: bytes) -> bytes:
    """Custom non-cryptographic hash (16 bytes)"""
    h = [0] * 16
    for i, byte in enumerate(data):
        h[i % 16] ^= byte
        h[i % 16] = (h[i % 16] + 31) % 256
    return bytes(h)

def simple_xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def simple_xor_decrypt(data: bytes, key: bytes) -> bytes:
    return simple_xor_encrypt(data, key)

def encrypt_with_hash(data: bytes, key: bytes) -> bytes:
    checksum = simple_hash(data)
    combined = data + checksum
    return simple_xor_encrypt(combined, key)

def decrypt_with_hash(data: bytes, key: bytes) -> bytes:
    decrypted = simple_xor_decrypt(data, key)
    content, recv_hash = decrypted[:-16], decrypted[-16:]
    if simple_hash(content) != recv_hash:
        raise ValueError("Integrity check failed: Custom hash mismatch.")
    return content


def send_message(sock, key, peer_port):
    msg = input("Enter message: ").encode()
    encrypted = encrypt_with_hash(msg, key)
    sock.sendto(b"msg" + encrypted, ("localhost", peer_port))
    print("[SENT] Message sent with integrity hash.")

def send_file(sock, key, peer_port):
    filepath = input("Enter file path: ").strip()
    if not os.path.isfile(filepath):
        print("[ERROR] File not found.")
        return
    with open(filepath, "rb") as f:
        file_data = f.read()
    encrypted = encrypt_with_hash(file_data, key)
    sock.sendto(b"file" + encrypted, ("localhost", peer_port))
    print(f"[SENT] File '{filepath}' sent with integrity check.")

def handle_incoming(sock, key):
    while True:
        data, addr = sock.recvfrom(65536)
        if data.startswith(b"msg"):
            try:
                content = decrypt_with_hash(data[3:], key)
                print(f"[MSG from {addr[1]}] {content.decode()}")
            except Exception as e:
                print(f"[ERROR] Message failed: {e}")
        elif data.startswith(b"file"):
            try:
                content = decrypt_with_hash(data[4:], key)
                filename = f"received_from_{addr[1]}.bin"
                with open(filename, "wb") as f:
                    f.write(content)
                print(f"[FILE RECEIVED] Saved as '{filename}'")
            except Exception as e:
                print(f"[ERROR] File failed: {e}")


def main():
    password = input("Enter shared password: ").encode()
    key = password[:16].ljust(16, b'0')  # Use first 16 bytes of password

    my_port = int(input("Enter your port (e.g., 5000): "))
    peer_port = int(input("Enter peer's port (e.g., 5001): "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("localhost", my_port))
    print(f"[LISTENING] on port {my_port}...")

    threading.Thread(target=handle_incoming, args=(sock, key), daemon=True).start()

    while True:
        cmd = input("Enter command [msg/file/exit]: ").strip().lower()
        if cmd == "msg":
            send_message(sock, key, peer_port)
        elif cmd == "file":
            send_file(sock, key, peer_port)
        elif cmd == "exit":
            print("[INFO] Exiting...")
            break
        else:
            print("[ERROR] Invalid command.")

if __name__ == "__main__":
    main()
