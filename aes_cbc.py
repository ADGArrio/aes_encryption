from Crypto import Random
from Crypto.Cipher import AES
import os
import os.path
import time
class Encryptor:
    def __init__(self, new_key):
        self.key = new_key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size = 256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size) # Initialization Vector -> Random string of AES.block_size (16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plain_text = fo.read()

        start_time = time.time()  # Record the start time

        enc = self.encrypt(plain_text, self.key)

        end_time = time.time()  # Record the end time

        # Calculate and print the time taken for encryption in ms
        encryption_time = (end_time - start_time) * 1000

        # Log the time measurement to a file
        with open("cbc_encryption_log.txt", "a") as log_file:
            log_file.write(f"Encryption Time for {file_name}: {encryption_time:0.2f} ms\n")

        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)

    def decrypt(self, cipherText, key):
        iv = cipherText[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(cipherText[AES.block_size:])
        return plain_text.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            cipherText = fo.read()

        start_time = time.time()  # Record the start time

        dec = self.decrypt(cipherText, self.key)

        end_time = time.time()  # Record the end time

        # Calculate and print the time taken for decryption
        decryption_time = (end_time - start_time) * 1000

        # Log the time measurement to a file
        with open("cbc_decryption_log.txt", "a") as log_file:
            log_file.write(f"Decryption Time for {file_name}: {decryption_time:0.2f} ms\n")

        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)

key = b'\x81k\xc9k\x9b\xed/\xd5\xaf\xfc\xc81\x97\x93>\xc8:\x11n\xb3\xbc\xe3\x8d?+\xbesw\x1fof\xf1'
enc = Encryptor(key)

if os.path.isfile('/Users/arriogonsalves/PyCharmProjects/aesEncryption/data.txt.enc'):
    while True:
        password = str(input("Enter Password: "))
        enc.decrypt_file("data.txt.enc")
        with open("data.txt") as f:
            p = f.readlines()
        if p[0] == password:
            enc.encrypt_file("data.txt")
            break
    while True:
        os.system('clear')
        choice = int(input("Choose as Appropriate:\n Press 1 to encrypt file\n Press 2 to decrypt file\n Press 3 to exit\n"))
        os.system('clear')
        if choice == 1:
            enc.encrypt_file(str(input("Enter name of file to encrypt: ")))
        elif choice == 2:
            enc.decrypt_file(str(input("Enter name of file to decrypt: ")))
        elif choice == 3:
            exit()
        else:
            print("Please select a valid option!")
else:
    while True:
        os.system('clear')
        password = str(input("Enter a password that will be used for decryption: "))
        confirm_password = str(input("Confirm password: "))
        if password == confirm_password:
            break
        else:
            print("Passwords Mismatched!")
    f = open("data.txt", "w+")
    f.write(password)
    f.close()
    enc.encrypt_file("data.txt")
    print("Please restart the program to complete the setup.")




