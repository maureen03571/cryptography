# week3_stream_randomness.py
# LFSR, RC4 simulation, and statistical randomness tests

import random
import statistics
from collections import Counter

# ---------- LFSR ----------
class LFSR:
    def __init__(self, seed, taps):
        self.state = seed & ((1 << 16) - 1)   # 16-bit
        self.taps = taps
        self.period = 0

    def next_bit(self):
        # XOR of tap bits
        feedback = 0
        for t in self.taps:
            feedback ^= (self.state >> t) & 1
        self.state = ((self.state << 1) | feedback) & ((1 << 16) - 1)
        return feedback

    def generate_bits(self, n):
        return [self.next_bit() for _ in range(n)]

# ---------- RC4 Simulation ----------
def rc4_keystream(key, length):
    S = list(range(256))
    j = 0
    # KSA
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    # PRGA
    i = 0
    j = 0
    keystream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream

def rc4_encrypt(plaintext, key):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    keystream = rc4_keystream(key, len(plaintext))
    ciphertext = bytes([p ^ k for p, k in zip(plaintext, keystream)])
    return ciphertext

# ---------- Randomness Tests ----------
def frequency_test(bits):
    n = len(bits)
    ones = sum(bits)
    zeros = n - ones
    s = abs(ones - zeros) / (n ** 0.5)
    p_value = 2 * (1 - (abs(s) / (2 ** 0.5)))  # simplified approximation
    return p_value

def runs_test(bits):
    n = len(bits)
    runs = 1
    for i in range(1, n):
        if bits[i] != bits[i-1]:
            runs += 1
    expected = (2 * n - 1) / 3
    variance = (16 * n - 29) / 90
    if variance <= 0:
        return 0.5
    z = (runs - expected) / (variance ** 0.5)
    p_value = 2 * (1 - abs(z))   # very crude approximation
    return max(0, min(1, p_value))

def mean_test(bits):
    return sum(bits) / len(bits)

# ---------- Main ----------
def main():
    print("=== LFSR Generator ===")
    lfsr = LFSR(seed=0b1010101010101010, taps=[13,14,15])  # example taps
    bits = lfsr.generate_bits(100)
    print(f"First 50 bits: {bits[:50]}")
    
    # Find period (naive)
    lfsr2 = LFSR(seed=0b1010101010101010, taps=[13,14,15])
    seen = {}
    period = 0
    for i in range(50000):
        state = lfsr2.state
        if state in seen:
            period = i - seen[state]
            break
        seen[state] = i
        lfsr2.next_bit()
    print(f"Period estimate: {period if period else '>50000'}")
    
    print("\n=== RC4 Simulation ===")
    plain = b"SECURE_MESSAGE"
    key = b"mysecretkey"
    cipher = rc4_encrypt(plain, key)
    decrypted = rc4_encrypt(cipher, key)
    print(f"Plain: {plain}")
    print(f"Ciphertext (hex): {cipher.hex()}")
    print(f"Decrypted: {decrypted}")
    
    print("\n=== Statistical Randomness Testing (LFSR bits) ===")
    test_bits = lfsr.generate_bits(1000)
    freq_p = frequency_test(test_bits)
    runs_p = runs_test(test_bits)
    mean = mean_test(test_bits)
    print(f"Frequency test p-value: {freq_p:.4f}")
    print(f"Runs test p-value: {runs_p:.4f}")
    print(f"Mean (proportion of ones): {mean:.4f} (ideal 0.5)")
    
    print("\n=== Encryption Performance ===")
    import time
    sizes = [1000, 10000, 100000]
    for sz in sizes:
        data = b"A" * sz
        start = time.time()
        _ = rc4_encrypt(data, b"test")
        elapsed = time.time() - start
        print(f"Size {sz:6d} bytes -> {elapsed:.6f} sec ({(sz/1024)/elapsed:.2f} KB/s)")

if __name__ == "__main__":
    main()