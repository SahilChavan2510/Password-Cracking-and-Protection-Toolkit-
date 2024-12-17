import hashlib
import bcrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import itertools
import time

def hash_password_simple(password):
    """Hashes a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def hash_password_bcrypt(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password_bcrypt(password, hashed):
    """Checks a bcrypt hashed password."""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def enforce_password_policy(password):
    """Checks password policy rules."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return "Password must include at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must include at least one number."
    return "Password is strong."

def encrypt_password(password, key):
    """Encrypts a password using AES encryption."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(password.encode()) + encryptor.finalize()
    return iv + encrypted

def decrypt_password(encrypted_data, key):
    """Decrypts a password encrypted using AES."""
    iv = encrypted_data[:16]
    encrypted = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted) + decryptor.finalize()).decode()
 
def dictionary_attack(target_hash, dictionary_file, hash_type="sha256"):
    """Attempts to crack the password using a dictionary attack."""
    try:
        with open(dictionary_file, 'r') as file:
            for line in file:
                guess = line.strip()
                if hash_type == "sha256" and hash_password_simple(guess) == target_hash:
                    return guess
                elif hash_type == "bcrypt" and check_password_bcrypt(guess, target_hash):
                    return guess
    except FileNotFoundError:
        print("Dictionary file not found. Skipping dictionary attack.")
    return None

def brute_force_hash(target_hash, charset, max_length, timeout=60):
    """Performs a brute-force attack to find the password matching the given hash."""
    start_time = time.time()
    for length in range(1, max_length + 1):
        for guess in itertools.product(charset, repeat=length):
            guess = ''.join(guess)
            if hash_password_simple(guess) == target_hash:
                return guess
            if time.time() - start_time > timeout:
                print("\n Brute-force attack timed out.")
                return None
    return None

def get_valid_password():
    """Prompts the user to enter a password until it meets the policy."""
    while True:
        password = input(" Enter a password: ")
        policy_check = enforce_password_policy(password)
        if policy_check == "Password is strong.":
            return password
        else:
            print(policy_check)

def main():
    print(" Password Cracking and Protection Toolkit \n")

    # Get a valid password from the user
    password = get_valid_password()

    # Example of hashing and encrypting the password
    hashed_password = hash_password_bcrypt(password)
    print(f"\n Hashed Password (bcrypt): {hashed_password}")

    key = os.urandom(32)  # AES key should be kept secret and consistent
    encrypted = encrypt_password(password, key)
    decrypted = decrypt_password(encrypted, key)
    print(f"\n Encrypted Password: {encrypted}")
    print(f"\n Decrypted Password: {decrypted}")

    # Use the hash of the entered password for cracking
    target_hash = hash_password_simple(password)
    print(f"\n Target Hash (SHA-256): {target_hash}")
 
    # Dictionary attack example
    dictionary_file = "dictionary.txt"
    cracked_password = dictionary_attack(target_hash, dictionary_file, hash_type="sha256")
    if cracked_password:
        print(f"\n Cracked Password (Dictionary): {cracked_password}")
    else:
        print("\n Password not found in dictionary.")

    # Brute-force attack example
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=~`'
    max_length = 8  # Limit to 4 characters for demonstration
    cracked_password = brute_force_hash(target_hash, charset, max_length, timeout=30)
    if cracked_password:
        print(f"Cracked Password (Brute Force): {cracked_password}")
    else:
        print(" Password not cracked via brute force.")

if __name__ == "__main__":
    main()