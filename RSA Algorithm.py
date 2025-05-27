import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair():
    """
    Generates a new RSA public and private key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Serializes a public key to PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key, password=None):
    """
    Serializes a private key to PEM format, optionally encrypted with a password.
    """
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password)
    else:
        encryption_algorithm = serialization.NoEncryption()

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

def deserialize_public_key(pem_data):
    """
    Deserializes a public key from PEM format.
    """
    return serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )

def deserialize_private_key(pem_data, password=None):
    """
    Deserializes a private key from PEM format, optionally with a password.
    """
    return serialization.load_pem_private_key(
        pem_data,
        password=password,
        backend=default_backend()
    )

def generate_symmetric_key(length_bytes=32):
    """
    Generates a random symmetric key of a specified length (e.g., 32 bytes for AES-256).
    """
    return os.urandom(length_bytes)

def encrypt_symmetric_key(symmetric_key, recipient_public_key):
    """
    Encrypts a symmetric key using the recipient's RSA public key.
    Uses OAEP padding for security.
    """
    encrypted_key = recipient_public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

def decrypt_symmetric_key(encrypted_key, recipient_private_key):
    """
    Decrypts an encrypted symmetric key using the recipient's RSA private key.
    """
    decrypted_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

def main():
    print("--- RSA Key Exchange Demonstration ---")

  
    print("\nAlice is generating her RSA key pair...")
    alice_private_key, alice_public_key = generate_rsa_key_pair()
    alice_public_pem = serialize_public_key(alice_public_key)
    print("Alice's Public Key (PEM format):\n", alice_public_pem.decode())

   
    print("\nBob is generating his RSA key pair...")
    bob_private_key, bob_public_key = generate_rsa_key_pair()
    bob_public_pem = serialize_public_key(bob_public_key)
    print("Bob's Public Key (PEM format):\n", bob_public_pem.decode())
    print("\nAlice generates a symmetric key for communication.")
    alice_symmetric_key = generate_symmetric_key()
    print(f"Alice's Symmetric Key (bytes): {alice_symmetric_key.hex()}")

   
    print("\nAlice encrypts the symmetric key using Bob's public key...")
    encrypted_symmetric_key = encrypt_symmetric_key(alice_symmetric_key, bob_public_key)
    print(f"Encrypted Symmetric Key (hex): {encrypted_symmetric_key.hex()} (length: {len(encrypted_symmetric_key)} bytes)")

   
    print("\nBob receives the encrypted key and decrypts it using his private key...")
    try:
        bob_decrypted_symmetric_key = decrypt_symmetric_key(encrypted_symmetric_key, bob_private_key)
        print(f"Bob's Decrypted Symmetric Key (bytes): {bob_decrypted_symmetric_key.hex()}")

       
        if alice_symmetric_key == bob_decrypted_symmetric_key:
            print("\nSUCCESS: Symmetric key exchanged successfully!")
        else:
            print("\nFAILURE: Symmetric key exchange failed!")
    except Exception as e:
        print(f"\nERROR during decryption: {e}")
        print("This often indicates incorrect key usage or corrupted data.")

if __name__ == "__main__":
    main()