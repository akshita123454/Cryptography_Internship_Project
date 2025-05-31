
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import socket
import threading
import os
import hashlib
import json
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_symmetric_key(symmetric_key, public_key):
    return public_key.encrypt(
        symmetric_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_symmetric_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )


def derive_key(password: str, salt: bytes = b'static_salt', key_len: int = 32) -> bytes:
    return PBKDF2(password, salt, dkLen=key_len)

def encrypt(data: bytes, key: bytes) -> bytes:
    hash_digest = hashlib.sha256(data).digest()
    full_data = data + hash_digest
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(full_data, AES.block_size))
    return iv + ciphertext

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)
    data, recv_hash = decrypted[:-32], decrypted[-32:]
    computed_hash = hashlib.sha256(data).digest()
    if recv_hash != computed_hash:
        raise ValueError("Integrity check failed.")
    return data


class SecureChatApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Chat GUI")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self.discovery_port = 6000
        self.active_clients = []
        self.running = True

        self.build_gui()

    def build_gui(self):
        frm = tk.Frame(self.master)
        frm.pack(padx=10, pady=10)

        tk.Label(frm, text="Your Port:").grid(row=0, column=0)
        self.my_port_entry = tk.Entry(frm)
        self.my_port_entry.grid(row=0, column=1)

        tk.Label(frm, text="Peer Port:").grid(row=1, column=0)
        self.peer_port_entry = tk.Entry(frm)
        self.peer_port_entry.grid(row=1, column=1)

        tk.Label(frm, text="Shared Password:").grid(row=2, column=0)
        self.password_entry = tk.Entry(frm, show='*')
        self.password_entry.grid(row=2, column=1)

        self.start_button = tk.Button(frm, text="Start Chat", command=self.start_chat)
        self.start_button.grid(row=3, columnspan=2, pady=5)

        self.output_box = scrolledtext.ScrolledText(self.master, width=60, height=15, state='disabled')
        self.output_box.pack(padx=10, pady=10)

        self.msg_entry = tk.Entry(self.master, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=(10,0), pady=(0,10))

        self.send_btn = tk.Button(self.master, text="Send Message", command=self.send_message)
        self.send_btn.pack(side=tk.LEFT, padx=5, pady=(0,10))

        self.file_btn = tk.Button(self.master, text="Send File", command=self.send_file)
        self.file_btn.pack(side=tk.LEFT, padx=5, pady=(0,10))

    def log(self, text):
        self.output_box.config(state='normal')
        self.output_box.insert(tk.END, text + "\n")
        self.output_box.config(state='disabled')
        self.output_box.see(tk.END)

    def start_chat(self):
        try:
            self.my_port = int(self.my_port_entry.get())
            self.peer_port = int(self.peer_port_entry.get())
            self.password = self.password_entry.get()

            self.key = derive_key(self.password)
            self.sock.bind(('', self.my_port))

            threading.Thread(target=self.listen_for_messages, daemon=True).start()
            threading.Thread(target=self.broadcast_presence, daemon=True).start()
            threading.Thread(target=self.listen_for_clients, daemon=True).start()

            self.log(f"[INFO] Listening on port {self.my_port}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def broadcast_presence(self):
        while self.running:
            presence = json.dumps({"port": self.my_port})
            self.sock.sendto(presence.encode(), ('255.255.255.255', self.discovery_port))
            time.sleep(5)

    def listen_for_clients(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(1024)
                try:
                    client = json.loads(data.decode())
                    if client not in self.active_clients and client["port"] != self.my_port:
                        self.active_clients.append(client)
                        self.log(f"[DISCOVERY] New client: {client}")
                except json.JSONDecodeError:
                    pass
            except:
                pass

    def listen_for_messages(self):
        while self.running:
            data, addr = self.sock.recvfrom(65536)
            if data.startswith(b'msg'):
                try:
                    decrypted = decrypt(data[3:], self.key).decode()
                    self.log(f"[{addr}] Message: {decrypted}")
                except Exception as e:
                    self.log(f"[ERROR] Decryption failed: {e}")
            elif data.startswith(b'file'):
                try:
                    decrypted = decrypt(data[4:], self.key)
                    filename = f"received_file_from_{addr[1]}.bin"
                    with open(filename, "wb") as f:
                        f.write(decrypted)
                    self.log(f"[{addr}] File received: {filename}")
                except Exception as e:
                    self.log(f"[ERROR] File integrity failed: {e}")

    def send_message(self):
        msg = self.msg_entry.get()
        if msg:
            encrypted = encrypt(msg.encode(), self.key)
            self.sock.sendto(b"msg" + encrypted, ("127.0.0.1", self.peer_port))
            self.log(f"[YOU] {msg}")
            self.msg_entry.delete(0, tk.END)

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                with open(filepath, "rb") as f:
                    file_data = f.read()
                encrypted = encrypt(file_data, self.key)
                self.sock.sendto(b"file" + encrypted, ("127.0.0.1", self.peer_port))
                self.log(f"[YOU] Sent file: {filepath}")
            except Exception as e:
                self.log(f"[ERROR] Failed to send file: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
