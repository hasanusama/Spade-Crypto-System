# COMP.SEC.220-2024-2025
# Creator: Muhammad Hasan Usama
# Student id number: 152148195
# Program: Spade Crypto System

from sympy import gcd, isprime
import random
from typing import List, Tuple
import sqlite3
from datetime import datetime
from math import gcd
import os
import psutil

# Move DNA mapping to global scope for reuse and efficiency
DNA_MAPPING = {
    "AA": 1, "AC": 2, "AG": 3, "AT": 4,
    "CA": 5, "CC": 6, "CG": 7, "CT": 8,
    "GA": 9, "GC": 10, "GG": 11, "GT": 12,
    "TA": 13, "TC": 14, "TG": 15, "TT": 16
}

# Function to get memory usage in KB
def get_memory_usage() -> float:
    # Get the memory usage of the current process
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    return memory_info.rss / 1024  # Convert bytes to KB

def generate_unique_db_name(prefix: str) -> str:
    """Generate a unique database name using a prefix."""
    # Ensure the DB folder exists
    db_folder = "dB"
    if not os.path.exists(db_folder):
        os.makedirs(db_folder)  # Create the folder if it doesn't exist

    # Generate the unique database file name
    unique_name = f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.db"
    db_path = os.path.join(db_folder, unique_name)  # Combine folder and file name
    return db_path


class Spade:
    def __init__(self, modulus: int, generator: int, max_vec_size: int):
        # Ensure generator and modulus are relatively prime
        if gcd(generator, modulus) != 1:
            raise ValueError("Generator and modulus are not relatively prime!")
        self.N = max_vec_size  # Maximum vector size
        self.Q = modulus  # Modulus for the group
        self.G = generator  # Generator of the group

    def setup(self) -> Tuple[List[int], List[int]]:
        # Generate secret and public keys
        sks, pks = [], []
        for _ in range(self.N):
            sk = self.random_element_in_zmod(self.Q)
            sks.append(sk)
            pk = pow(self.G, sk, self.Q)  # Public key = G^sk mod Q
            pks.append(pk)
        return sks, pks

    def register(self, alpha: int) -> int:
        # Register the user with alpha as their secret value
        return pow(self.G, alpha, self.Q)

    def encrypt(self, pks: List[int], alpha: int, data: List[int]) -> List[Tuple[int, int]]:
        # Encrypt each value in the data vector
        if len(data) != self.N:
            raise ValueError("Input vector length does not match setup parameters.")
        ciphertexts = []
        for i in range(self.N):
            r = self.random_element_in_zmod(self.Q)  # Random nonce
            c0 = pow(self.G, r + alpha, self.Q)  # Ciphertext component 0
            m_i = data[i]
            c1 = (pow(pks[i], alpha, self.Q) * pow(pow(self.G, r, self.Q), m_i, self.Q)) % self.Q
            ciphertexts.append((c0, c1))
        return ciphertexts

    def key_derivation(self, user_value: int, sks: List[int], reg_key: int) -> List[int]:
        # Derive keys for decryption
        dk = []
        for sk in sks:
            vs = (user_value - sk) % self.Q  # Adjust value to modulus
            dk.append(pow(reg_key, vs, self.Q))  # Derived key = reg_key^vs mod Q
        return dk

    def decrypt(self, dk: List[int], user_value: int, ciphertexts: List[Tuple[int, int]]) -> List[int]:
        # Decrypt ciphertexts using derived keys
        results = []
        for i, (c0, c1) in enumerate(ciphertexts):
            # Calculate the inverse of user_value in the group
            vb = -user_value
            exp = (self.Q - 1 + vb) % (self.Q - 1) if vb < 0 else vb
            yi = (c1 * pow(c0, exp, self.Q)) % self.Q  # Partial decryption
            yi = (yi * dk[i]) % self.Q  # Apply derived key
            results.append(yi)
        return results

    @staticmethod
    def random_element_in_zmod(q: int) -> int:
        # Generate a random odd value within the group
        value = random.randint(1, q - 1)
        return value if value % 2 != 0 else value + 1

def generate_master_secret_key(q: int) -> int:
    # Create a master secret key
    return Spade.random_element_in_zmod(q)

def generate_master_public_key(secret_key: int, g: int, q: int) -> int:
    # Generate a public key from the secret key
    return pow(g, secret_key, q)

def convert_dna_to_int(dna_sequence: str) -> List[int]:
    # Convert a DNA sequence into a list of integers
    data = []
    for i in range(0, len(dna_sequence) - 1, 2):
        dna_pair = dna_sequence[i:i+2]
        if dna_pair in DNA_MAPPING:
            data.append(DNA_MAPPING[dna_pair])
        else:
            raise ValueError(f"Invalid DNA sequence pair: {dna_pair}")
    return data

def save_encrypted_data_to_database(encrypted_data: List[Tuple[int, int]], db_path: str):
    # Save encrypted data to an SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS EncryptedData (C0 TEXT, C1 TEXT)")
    for c0, c1 in encrypted_data:
        cursor.execute("INSERT INTO EncryptedData (C0, C1) VALUES (?, ?)", (str(c0), str(c1)))
    conn.commit()
    conn.close()

def print_index(search_value: int, decrypted_data: List[int]):
    # Print the indexes where the search value matches in the decrypted data
    matching_indexes = [i for i in range(len(decrypted_data)) if decrypted_data[i] == search_value]
    if matching_indexes:
        print(f"The search value appears at indexes: {', '.join(map(str, matching_indexes))}")
    else:
        print(f"The search value does not appear in the decrypted data.")

def main():
    # Main entry point
    option = input("Enter 1 for Hypnogram and 2 for DNA: ")
    max_vec_length = int(input("Enter the maximum vector length: "))
    data = []

    try:
        overall_start_time = datetime.now()  # Overall timer

        # Cryptosystem parameters
        modulus = 257  # A Fermat prime, so modulus - 1 = 256 is a power of 2
        generator = 3
        db_path = generate_unique_db_name("encrypted_data")

        if option == "1":
            file_path = "dataset//Hypnogram.txt"
            print("Processing Hypnogram...")
            with open(file_path, "r") as file:
                for line in file:
                    if len(data) >= max_vec_length:  # Stop reading if limit is reached
                        break
                    if line.strip().isdigit():  # Only process valid integers
                        data.append(int(line.strip()))
        elif option == "2":
            file_path = "dataset//DNA.txt"
            print("Processing DNA sequence...")
            dna_sequence = ""
            with open(file_path, "r") as file:
                for line in file:
                    if len(dna_sequence) >= max_vec_length * 2:  # Stop when enough DNA pairs are read
                        break
                    dna_sequence += line.strip().replace(" ", "").upper()  # Clean and accumulate DNA sequence
                    # Convert only the required number of DNA pairs to integers
                data = convert_dna_to_int(dna_sequence[:max_vec_length * 2])  # Each pair is 2 characters

        print(f"Data Vector Length: {len(data)}")

        # Cryptosystem setup
        start_time = datetime.now()
        initial_memory = get_memory_usage()  # Memory before setup
        spade = Spade(modulus, generator, len(data))
        sks, pks = spade.setup()
        setup_time = (datetime.now() - start_time).total_seconds()
        setup_memory = get_memory_usage() - initial_memory  # Memory after setup

        # User registration
        start_time = datetime.now()
        initial_memory = get_memory_usage()
        alpha = 59
        reg_key = spade.register(alpha)
        register_time = (datetime.now() - start_time).total_seconds()
        register_memory = get_memory_usage() - initial_memory

        # Encryption
        start_time = datetime.now()
        initial_memory = get_memory_usage()
        encrypted_data = spade.encrypt(pks, alpha, data)
        encryption_time = (datetime.now() - start_time).total_seconds()
        encryption_memory = get_memory_usage() - initial_memory

        # Save encrypted data to database
        save_encrypted_data_to_database(encrypted_data, db_path)

        # Key derivation
        print("\n--- Data Analyst Part ---")
        search_value = input("Hello DA, enter the search value: ")
        if option == "1":
            search_value = int(search_value)
        elif option == "2":
            search_value = DNA_MAPPING[search_value]
        start_time = datetime.now()
        initial_memory = get_memory_usage()
        derived_keys = spade.key_derivation(search_value, sks, reg_key)
        key_derivation_time = (datetime.now() - start_time).total_seconds()
        key_derivation_memory = get_memory_usage() - initial_memory

        # Decryption
        start_time = datetime.now()
        initial_memory = get_memory_usage()
        decrypted_data = spade.decrypt(derived_keys, search_value, encrypted_data)
        decryption_time = (datetime.now() - start_time).total_seconds()
        decryption_memory = get_memory_usage() - initial_memory

        # Print matching indexes
        print("\n--- Matching Index ---")
        print_index(search_value, decrypted_data)

        # Print timing and memory usage details
        total_processing_time = (datetime.now() - overall_start_time).total_seconds()
        print("\n--- Timing and Memory Details ---")
        print(f"Setup Time: {setup_time:.6f} seconds, Memory Used: {setup_memory:.2f} KB")
        print(f"Register Time: {register_time:.6f} seconds, Memory Used: {register_memory:.2f} KB")
        print(f"Encryption Time: {encryption_time:.6f} seconds, Memory Used: {encryption_memory:.2f} KB")
        print(f"Key Derivation Time: {key_derivation_time:.6f} seconds, Memory Used: {key_derivation_memory:.2f} KB")
        print(f"Decryption Time: {decryption_time:.6f} seconds, Memory Used: {decryption_memory:.2f} KB")
        print(f"Total Processing Time: {total_processing_time:.6f} seconds")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
