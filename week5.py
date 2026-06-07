# week5_rsa.py
# RSA key generation, encryption/decryption, and validation

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import time

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename="private_key.pem"):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)
    print(f"Private key saved to {filename}")

def save_public_key(public_key, filename="public_key.pem"):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)
    print(f"Public key saved to {filename}")

def load_private_key(filename="private_key.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(filename="public_key.pem"):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def benchmark_key_sizes():
    sizes = [1024, 2048, 4096]
    results = []
    msg = b"Confidential message for testing RSA performance."
    for sz in sizes:
        start = time.time()
        priv = rsa.generate_private_key(public_exponent=65537, key_size=sz)
        pub = priv.public_key()
        gen_time = time.time() - start
        
        start = time.time()
        ct = rsa_encrypt(pub, msg)
        enc_time = time.time() - start
        
        start = time.time()
        pt = rsa_decrypt(priv, ct)
        dec_time = time.time() - start
        
        results.append((sz, gen_time, enc_time, dec_time))
    return results

def main():
    print("=== RSA Key Generation ===")
    private_key, public_key = generate_rsa_keys()
    save_private_key(private_key)
    save_public_key(public_key)
    
    print("\n=== Encryption / Decryption ===")
    plain = b"CONFIDENTIAL"
    cipher = rsa_encrypt(public_key, plain)
    decrypted = rsa_decrypt(private_key, cipher)
    print(f"Plaintext: {plain}")
    print(f"Ciphertext (hex): {cipher.hex()[:64]}...")
    print(f"Decrypted: {decrypted}")
    
    print("\n=== Secure Message Transmission Simulation ===")
    # Sender encrypts with receiver's public key
    receiver_public = public_key
    message = b"Hello, this is a secure message for you."
    ciphertext = rsa_encrypt(receiver_public, message)
    # Receiver decrypts with own private key
    received_plain = rsa_decrypt(private_key, ciphertext)
    print(f"Sent: {message}")
    print(f"Received and decrypted: {received_plain}")
    
    print("\n=== RSA Performance Validation (Key size comparison) ===")
    results = benchmark_key_sizes()
    print(f"{'Key size':<10} {'Gen (s)':<10} {'Enc (s)':<10} {'Dec (s)':<10}")
    for sz, gen, enc, dec in results:
        print(f"{sz:<10} {gen:<10.4f} {enc:<10.4f} {dec:<10.4f}")

if __name__ == "__main__":
    main()