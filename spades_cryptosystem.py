# COMP.SEC.220-2024-2025
# Creator: Muhammad Hasan Usama
# Student id number: 152148195
# Program: Spade Crypto System

# crypto_operations.py
import os
import random
import sqlite3
import psutil
from datetime import datetime
from typing import List, Tuple
from math import gcd

DNA_MAPPING = {
    "AA": 1, "AC": 2, "AG": 3, "AT": 4,
    "CA": 5, "CC": 6, "CG": 7, "CT": 8,
    "GA": 9, "GC": 10, "GG": 11, "GT": 12,
    "TA": 13, "TC": 14, "TG": 15, "TT": 16
}

def get_memory_usage() -> float:
    process = psutil.Process(os.getpid())
    memory_info = process.memory_info()
    return memory_info.rss / 1024  # in KB

def generate_unique_db_name(prefix: str) -> str:
    db_folder = "dB"
    os.makedirs(db_folder, exist_ok=True)
    unique_name = f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.db"
    return os.path.join(db_folder, unique_name)

class Spade:
    def __init__(self, modulus: int, generator: int, max_vec_size: int):
        if gcd(generator, modulus) != 1:
            raise ValueError("Generator and modulus must be relatively prime.")
        self.N = max_vec_size
        self.Q = modulus
        self.G = generator

    def setup(self) -> Tuple[List[int], List[int]]:
        sks, pks = [], []
        for _ in range(self.N):
            sk = self.random_element_in_zmod(self.Q)
            sks.append(sk)
            pk = pow(self.G, sk, self.Q)
            pks.append(pk)
        return sks, pks

    def register(self, alpha: int) -> int:
        return pow(self.G, alpha, self.Q)

    def encrypt(self, pks: List[int], alpha: int, data: List[int]) -> List[Tuple[int, int]]:
        if len(data) != self.N:
            raise ValueError("Data length mismatch.")
        ciphertexts = []
        for i in range(self.N):
            r = self.random_element_in_zmod(self.Q)
            c0 = pow(self.G, r + alpha, self.Q)
            m_i = data[i]
            c1 = (pow(pks[i], alpha, self.Q) * pow(pow(self.G, r, self.Q), m_i, self.Q)) % self.Q
            ciphertexts.append((c0, c1))
        return ciphertexts

    def key_derivation(self, user_value: int, sks: List[int], reg_key: int) -> List[int]:
        return [pow(reg_key, (user_value - sk) % self.Q, self.Q) for sk in sks]

    def decrypt(self, dk: List[int], user_value: int, ciphertexts: List[Tuple[int, int]]) -> List[int]:
        results = []
        for i, (c0, c1) in enumerate(ciphertexts):
            vb = -user_value
            exp = (self.Q - 1 + vb) % (self.Q - 1) if vb < 0 else vb
            yi = (c1 * pow(c0, exp, self.Q)) % self.Q
            yi = (yi * dk[i]) % self.Q
            results.append(yi)
        return results

    @staticmethod
    def random_element_in_zmod(q: int) -> int:
        value = random.randint(1, q - 1)
        return value if value % 2 != 0 else value + 1

def convert_dna_to_int(dna_sequence: str) -> List[int]:
    data = []
    for i in range(0, len(dna_sequence) - 1, 2):
        pair = dna_sequence[i:i+2]
        if pair in DNA_MAPPING:
            data.append(DNA_MAPPING[pair])
        else:
            raise ValueError(f"Invalid DNA pair: {pair}")
    return data

def save_encrypted_data_to_database(encrypted_data: List[Tuple[int, int]], db_path: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS EncryptedData (C0 TEXT, C1 TEXT)")
    for c0, c1 in encrypted_data:
        cursor.execute("INSERT INTO EncryptedData (C0, C1) VALUES (?, ?)", (str(c0), str(c1)))
    conn.commit()
    conn.close()

def encrypt_dataset(option: str, max_vec_length: int, alpha: int = 59) -> Tuple[str, List[int], List[Tuple[int, int]], List[int], int]:
    modulus = 257
    generator = 3
    data = []

    if option == "1":
        file_path = os.path.join("dataset", "Hypnogram.txt")
        with open(file_path, "r") as file:
            for line in file:
                if len(data) >= max_vec_length:
                    break
                if line.strip().isdigit():
                    data.append(int(line.strip()))
    elif option == "2":
        file_path = os.path.join("dataset", "DNA.txt")
        dna_sequence = ""
        with open(file_path, "r") as file:
            for line in file:
                if len(dna_sequence) >= max_vec_length * 2:
                    break
                dna_sequence += line.strip().replace(" ", "").upper()
        data = convert_dna_to_int(dna_sequence[:max_vec_length * 2])
    else:
        raise ValueError("Invalid data type option.")

    spade = Spade(modulus, generator, len(data))
    sks, pks = spade.setup()
    reg_key = spade.register(alpha)
    encrypted_data = spade.encrypt(pks, alpha, data)
    db_path = generate_unique_db_name("encrypted_data")
    save_encrypted_data_to_database(encrypted_data, db_path)

    return db_path, data, encrypted_data, sks, reg_key

def search_and_decrypt(search_value: str, option: str, encrypted_data: List[Tuple[int, int]], sks: List[int], reg_key: int) -> List[int]:
    if option == "2":
        search_value = DNA_MAPPING[search_value]
    else:
        search_value = int(search_value)

    modulus = 257
    generator = 3
    spade = Spade(modulus, generator, len(encrypted_data))
    dk = spade.key_derivation(search_value, sks, reg_key)
    return spade.decrypt(dk, search_value, encrypted_data)
