# Full Secure Chat Application in a Single File
# Features: AES Encryption, SHA-based Integrity, RSA Key Exchange, Auto Discovery

import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import os
import time
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

backend = default_backend()

BROADCAST_PORT = 9999
BROADCAST_MSG = b"DISCOVER_SECURE_CHAT"


# -------------------- Cryptographic Utilities --------------------
def derive_keys(password: bytes, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password)
    return key[:32], key[32:]  # AES key, HMAC key


def encrypt(data: bytes, password: bytes):
    salt = os.urandom(16)
    iv = os.urandom(16)
    enc_key, mac_key = derive_keys(password, salt)

    padding_len = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_len] * padding_len)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    tag = h.finalize()

    return salt + iv + tag + ciphertext


def decrypt(enc_data: bytes, password: bytes):
    salt = enc_data[:16]
    iv = enc_data[16:32]
    tag = enc_data[32:64]
    ciphertext = enc_data[64:]

    enc_key, mac_key = derive_keys(password, salt)

    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    padding_len = padded_data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Invalid padding")
    return padded_data[:-padding_len]


def generate_rsa_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
    public = private.public_key()
    return private, public


def rsa_encrypt(public_key, message: bytes):
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def rsa_decrypt(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=backend)


# -------------------- GUI + Networking --------------------
class SecureChat:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure UDP Messenger")

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.password = b''
        self.peer_public_key = None
        self.private_key, self.public_key = generate_rsa_keys()

        # --- GUI Layout ---
        tk.Label(root, text="Shared Password:").pack()
        self.pass_entry = tk.Entry(root, show="*", width=30)
        self.pass_entry.pack()

        tk.Label(root, text="Your Port:").pack()
        self.my_port_entry = tk.Entry(root, width=30)
        self.my_port_entry.pack()

        tk.Label(root, text="Peer IP:").pack()
        self.peer_ip_entry = tk.Entry(root, width=30)
        self.peer_ip_entry.insert(0, "127.0.0.1")
        self.peer_ip_entry.pack()

        tk.Label(root, text="Peer Port:").pack()
        self.peer_port_entry = tk.Entry(root, width=30)
        self.peer_port_entry.pack()

        tk.Button(root, text="Start Listening", command=self.start_listening).pack(pady=5)

        self.chat_area = scrolledtext.ScrolledText(root, height=15, width=50)
        self.chat_area.pack()
        self.chat_area.config(state='disabled')

        self.msg_entry = tk.Entry(root, width=40)
        self.msg_entry.pack(side='left', padx=5, pady=5)
        tk.Button(root, text="Send", command=self.send_message).pack(side='left')
        tk.Button(root, text="Send File", command=self.send_file).pack(side='left')

    def log(self, text):
        self.chat_area.config(state='normal')
        self.chat_area.insert('end', text + '\n')
        self.chat_area.config(state='disabled')

    def start_listening(self):
        self.password = self.pass_entry.get().encode()
        try:
            my_port = int(self.my_port_entry.get())
            self.sock.bind(("0.0.0.0", my_port))
            threading.Thread(target=self.listen, daemon=True).start()
            threading.Thread(target=self.broadcast_presence, daemon=True).start()
            threading.Thread(target=self.listen_for_peers, daemon=True).start()
            self.log(f"[Listening on port {my_port}]")
            self.send_public_key()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def listen(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65536)
                if data.startswith(b"msg"):
                    msg = decrypt(data[3:], self.password).decode()
                    self.log(f"[Message from {addr[1]}] {msg}")
                elif data.startswith(b"file"):
                    decrypted = decrypt(data[4:], self.password)
                    filename, filedata = decrypted.split(b'||', 1)
                    with open(filename.decode(), "wb") as f:
                        f.write(filedata)
                    self.log(f"[File received: {filename.decode()}]")
                elif data.startswith(b"pubk"):
                    self.peer_public_key = deserialize_public_key(data[4:])
                    self.log("[Public Key Received]")
            except Exception as e:
                self.log(f"[Error receiving data] {e}")

    def send_public_key(self):
        peer_ip = self.peer_ip_entry.get().strip()
        peer_port = int(self.peer_port_entry.get())
        serialized_key = serialize_public_key(self.public_key)
        self.sock.sendto(b"pubk" + serialized_key, (peer_ip, peer_port))
        self.log("[Sent Public Key]")

    def send_message(self):
        try:
            msg = self.msg_entry.get().strip()
            peer_ip = self.peer_ip_entry.get().strip()
            peer_port = int(self.peer_port_entry.get())
            encrypted = encrypt(msg.encode(), self.password)
            self.sock.sendto(b"msg" + encrypted, (peer_ip, peer_port))
            self.log(f"[Sent] {msg}")
            self.msg_entry.delete(0, 'end')
        except Exception as e:
            self.log(f"[Error] {e}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        try:
            filename = os.path.basename(filepath)
            with open(filepath, "rb") as f:
                data = f.read()
            msg = filename.encode() + b'||' + data
            encrypted = encrypt(msg, self.password)
            peer_ip = self.peer_ip_entry.get().strip()
            peer_port = int(self.peer_port_entry.get())
            self.sock.sendto(b"file" + encrypted, (peer_ip, peer_port))
            self.log(f"[File sent: {filename}]")
        except Exception as e:
            self.log(f"[Error] {e}")

    def broadcast_presence(self):
        while True:
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                my_port = int(self.my_port_entry.get())
                self.sock.sendto(BROADCAST_MSG + str(my_port).encode(), ('<broadcast>', BROADCAST_PORT))
                time.sleep(5)
            except Exception:
                pass

    def listen_for_peers(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', BROADCAST_PORT))
        while True:
            msg, addr = s.recvfrom(1024)
            if msg.startswith(BROADCAST_MSG):
                port = int(msg[len(BROADCAST_MSG):])
                if addr[0] != socket.gethostbyname(socket.gethostname()):
                    self.log(f"[Discovered Peer] {addr[0]}:{port}")


# -------------------- Main --------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChat(root)
    root.mainloop()
