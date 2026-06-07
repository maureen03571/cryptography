# week2_classical_ciphers.py
# Caesar and Vigenère cipher implementation with input validation

def caesar_encrypt(text, shift):
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)   # preserve spaces/punctuation
    return ''.join(result)

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text, key):
    result = []
    key_idx = 0
    key = key.upper()
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def vigenere_decrypt(text, key):
    result = []
    key_idx = 0
    key = key.upper()
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def main():
    print("=== Caesar Cipher ===")
    plain_caesar = "HELLO"
    shift = 3
    enc_caesar = caesar_encrypt(plain_caesar, shift)
    dec_caesar = caesar_decrypt(enc_caesar, shift)
    print(f"Plain: {plain_caesar} -> Cipher: {enc_caesar} -> Dec: {dec_caesar}")

    print("\n=== Vigenère Cipher ===")
    plain_vig = "CRYPTO"
    key = "KEY"
    enc_vig = vigenere_encrypt(plain_vig, key)
    dec_vig = vigenere_decrypt(enc_vig, key)
    print(f"Plain: {plain_vig} -> Cipher: {enc_vig} -> Dec: {dec_vig}")

    print("\n=== User Input Validation (Caesar) ===")
    try:
        user_text = input("Enter text to encrypt (letters only): ")
        if not any(ch.isalpha() for ch in user_text):
            raise ValueError("No alphabetic characters found.")
        user_shift = int(input("Enter shift (integer): "))
        print(f"Encrypted: {caesar_encrypt(user_text, user_shift)}")
    except ValueError as e:
        print(f"Invalid input: {e}")

    print("\n=== Testing Results Table ===")
    print(f"{'Cipher':<12} {'Plaintext':<12} {'Ciphertext':<12} {'Time (approx)':<12}")
    import time
    start = time.time()
    _ = caesar_encrypt("A"*10000, 5)
    t_caesar = time.time() - start
    start = time.time()
    _ = vigenere_encrypt("A"*10000, "KEY")
    t_vigenere = time.time() - start
    print(f"{'Caesar':<12} {'HELLO':<12} {enc_caesar:<12} {t_caesar:.6f}s")
    print(f"{'Vigenère':<12} {'CRYPTO':<12} {enc_vig:<12} {t_vigenere:.6f}s")

if __name__ == "__main__":
    main()