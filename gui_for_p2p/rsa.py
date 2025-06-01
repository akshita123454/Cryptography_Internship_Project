import socket
import threading
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ---------- RSA Key Utilities ----------

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key, private_key.public_key()

def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend=default_backend())

def encrypt_symmetric_key(sym_key, public_key):
    return public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_symmetric_key(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ---------- Key Exchange Logic ----------

class KeyExchangeClient:
    def __init__(self, my_port, peer_port):
        self.my_port = my_port
        self.peer_port = peer_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("localhost", self.my_port))

        self.private_key, self.public_key = generate_rsa_key_pair()
        self.peer_public_key = None
        self.symmetric_key = None

    def send_public_key(self):
        pub_key_pem = serialize_key(self.public_key)
        self.sock.sendto(b"key" + pub_key_pem, ("localhost", self.peer_port))
        print(f"[SENT] Public key sent to peer at port {self.peer_port}.")

    def receive_public_key(self):
        while self.peer_public_key is None:
            data, _ = self.sock.recvfrom(2048)
            if data.startswith(b"key"):
                self.peer_public_key = deserialize_public_key(data[3:])
                print(f"[RECEIVED] Peer public key received on port {self.my_port}.")

    def send_encrypted_symmetric_key(self):
        self.symmetric_key = os.urandom(32)
        encrypted = encrypt_symmetric_key(self.symmetric_key, self.peer_public_key)
        self.sock.sendto(b"sym" + encrypted, ("localhost", self.peer_port))
        print(f"[SENT] Encrypted symmetric key sent to peer at port {self.peer_port}.")

    def receive_encrypted_symmetric_key(self):
        while self.symmetric_key is None:
            data, _ = self.sock.recvfrom(2048)
            if data.startswith(b"sym"):
                try:
                    decrypted = decrypt_symmetric_key(data[3:], self.private_key)
                    self.symmetric_key = decrypted
                    print(f"[RECEIVED] Decrypted symmetric key on port {self.my_port}.")
                except Exception as e:
                    print(f"[ERROR] Decryption failed: {e}")

    def run_key_exchange(self):
        print(f"\n[INFO] Running RSA key exchange from port {self.my_port} to {self.peer_port}...\n")
        threading.Thread(target=self.receive_public_key, daemon=True).start()
        threading.Thread(target=self.receive_encrypted_symmetric_key, daemon=True).start()

        time.sleep(2)
        self.send_public_key()
        time.sleep(2)
        self.send_encrypted_symmetric_key()

        # Wait until symmetric key is received or exchanged
        while self.symmetric_key is None:
            time.sleep(1)
        print(f"\n[SECURE] Final symmetric key (hex): {self.symmetric_key.hex()}")


if __name__ == "__main__":
    import os
    my_port = int(input("Enter your listening port (e.g., 5001): "))
    peer_port = int(input("Enter your peer's port (e.g., 5002): "))
    client = KeyExchangeClient(my_port, peer_port)
    client.run_key_exchange()
