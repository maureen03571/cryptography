# week6_hashing_auth.py
# SHA-256, bcrypt with salt, login simulation and security testing

import hashlib
import bcrypt
import time

def sha256_hash(data):
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def avalanche_test():
    print("=== Avalanche Effect (SHA-256) ===")
    msg1 = "password123"
    msg2 = "password124"   # only last character changed
    hash1 = sha256_hash(msg1)
    hash2 = sha256_hash(msg2)
    # count differing bits
    bits1 = bin(int(hash1, 16))[2:].zfill(256)
    bits2 = bin(int(hash2, 16))[2:].zfill(256)
    diff = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))
    print(f"Hash1: {hash1}")
    print(f"Hash2: {hash2}")
    print(f"Different bits: {diff} out of 256 ({diff/256*100:.1f}%)")

class PasswordAuth:
    def __init__(self, rounds=10):
        self.rounds = rounds
        self.storage = {}   # user -> (salt+hash) as string
    
    def register(self, username, password):
        salt = bcrypt.gensalt(rounds=self.rounds)
        hashed = bcrypt.hashpw(password.encode(), salt)
        self.storage[username] = hashed
        print(f"User '{username}' registered (hash stored).")
    
    def login(self, username, password):
        if username not in self.storage:
            return False
        stored_hash = self.storage[username]
        return bcrypt.checkpw(password.encode(), stored_hash)

def rainbow_rainbow_resistance_demo():
    print("\n=== Rainbow Table Resistance ===")
    password = "commonpassword"
    # Without salt: same password -> same hash
    hash_nosalt = hashlib.sha256(password.encode()).hexdigest()
    # With bcrypt (includes salt)
    salt = bcrypt.gensalt()
    hash_salted = bcrypt.hashpw(password.encode(), salt)
    salt2 = bcrypt.gensalt()
    hash_salted2 = bcrypt.hashpw(password.encode(), salt2)
    print(f"SHA-256 (no salt): {hash_nosalt}")
    print(f"bcrypt with salt1: {hash_salted}")
    print(f"bcrypt with salt2: {hash_salted2}")
    print("Even same password gives completely different bcrypt hashes -> rainbow tables useless.")

def brute_force_simulation(weak_password):
    print(f"\n=== Brute-force simulation against '{weak_password}' ===")
    target_hash = bcrypt.hashpw(weak_password.encode(), bcrypt.gensalt(rounds=8))
    # Simulate trying common passwords
    common_passwords = ["123456", "password", "qwerty", "admin", weak_password]
    start = time.time()
    found = None
    for guess in common_passwords:
        if bcrypt.checkpw(guess.encode(), target_hash):
            found = guess
            break
    elapsed = time.time() - start
    if found:
        print(f"Cracked! Password was '{found}' (time: {elapsed:.4f}s)")
    else:
        print("Not found in common list.")

def main():
    # SHA-256 demo
    print("=== SHA-256 Hash Generation ===")
    text = "password123"
    print(f"Input: {text}")
    print(f"Hash: {sha256_hash(text)}")
    
    avalanche_test()
    
    # Authentication system
    print("\n=== Password Authentication System (bcrypt) ===")
    auth = PasswordAuth(rounds=10)
    auth.register("alice", "SecurePass!2024")
    auth.register("bob", "bob123")
    
    print("Login attempt: alice with 'SecurePass!2024' ->", auth.login("alice", "SecurePass!2024"))
    print("Login attempt: alice with 'wrongpass' ->", auth.login("alice", "wrongpass"))
    
    rainbow_rainbow_resistance_demo()
    
    # Weak password test
    brute_force_simulation("password")
    
    print("\n=== Hash Verification Results ===")
    # Show stored hashes (they are safe)
    for user, h in auth.storage.items():
        print(f"{user}: {h[:30]}... (salt+hash stored safely)")

if __name__ == "__main__":
    main()