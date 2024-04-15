import csv
from hmac import digest

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

class data_encryption:
    def __init__(self, password):
        self.password = password

    def encrypt(self, plain_text):
        # Generating a random salt, deriving a key from the password and salt with PBKDF2
        salt_val = get_random_bytes(16)
        key_val = PBKDF2(self.password.encode('utf-8'), salt_val, dkLen=32, count=1000000, hmac_hash_module=SHA256)

        # an AES cipher object is created
        cipher = AES.new(key_val, AES.MODE_GCM)

        # Here, Encrypting the plaintext and generating ciphertext
        cipher_text, tag = cipher.encrypt_and_digest(pad(plain_text.encode('utf-8'), AES.block_size))

        # ciphertext, nonce, tag, and salt is returned
        return cipher_text, cipher.nonce, tag, salt_val

    def decrypt(self, cipher_text, nonce, tag, salt_val):
        # deriving a key from the password and salt with PBKDF2
        key_val = PBKDF2(self.password.encode('utf-8'), salt_val, dkLen=32, count=1000000, hmac_hash_module=SHA256)

        # again an AES cipher object is created
        cipher = AES.new(key_val, AES.MODE_GCM, nonce=nonce)

        # Decrypting and verifying the ciphertext
        try:
            plain_text = unpad(cipher.decrypt_and_verify(cipher_text, tag), AES.block_size)
        except ValueError as e:
            print(f"Decryption is failed: {e}")
            return None

        #  decrypted plaintext is returned
        return plain_text.decode('utf-8')

# Function for reading CSV file and combining the given data into a single string
def read_csv_file(filename):
    data_list = []
    with open(filename, "r", encoding="utf-8") as file:
        reader = csv.reader(file)
        for row in reader:
            # each row's values with a comma are joined and appended to data list
            data_list.append(",".join(row))
    # all rows are joined using a newline character to form a single string
    return "\n".join(data_list)

# a password is set for encryption and decryption
password = "12345678"

# reading the CSV file
filename = "data.csv"  # Specify your CSV file name here
plain_text = read_csv_file(filename)

# an instance of the DataEncryption class along with the password is created
encryption_instance = data_encryption(password)

# Encrypting the CSV dataset
cipher_text, nonce, tag, salt_val = encryption_instance.encrypt(plain_text)

# printing encrypted data
print("Encrypted data:", cipher_text)
print("Nonce value:", nonce)
print("Tag value:", tag)
print("Salt value:", salt_val)

# Decrypting the ciphertext with the same password and salt
decrypted_plaintext = encryption_instance.decrypt(cipher_text, nonce, tag, salt_val)

# printing the decrypted text and verify whether it matches the original text
print("Great ! , the decrypted plaintext matches the original plaintext:", decrypted_plaintext == plain_text)
print("Decrypted plaintext is:", decrypted_plaintext)

