from Crypto.Cipher import AES
import os
import time

class GCMEncryptor:
    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return cipher.nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext

    def encrypt_file(self, input_file):
        output_file = input_file + ".enc"
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        start_time = time.time()  # Record the start time

        nonce, ciphertext, tag = self.encrypt(plaintext)

        end_time = time.time()  # Record the end time


        with open(output_file, 'wb') as f:
            f.write(nonce + ciphertext + tag)

        encryption_time_ms = (end_time - start_time) * 1000

        # Log the encryption time
        with open("gcm_encryption_log.txt", "a") as log_file:
            log_file.write(f"Encryption Time for {input_file}: {encryption_time_ms:.2f} ms\n")

        # Remove the original unencrypted file
        os.remove(input_file)

    def decrypt_file(self, input_file):
        if not input_file.endswith(".enc"):
            print("Invalid input file format. It should have a '.enc' extension.")
            return

        output_file = input_file[:-4]  # Remove the '.enc' extension
        with open(input_file, 'rb') as f:
            encrypted_data = f.read()

        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:-16]
        tag = encrypted_data[-16:]

        start_time = time.time()  # Record the start time

        plaintext = self.decrypt(nonce, ciphertext, tag)

        end_time = time.time()  # Record the end time

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        decryption_time_ms = (end_time - start_time) * 1000

        # Log the decryption time
        with open("gcm_decryption_log.txt", "a") as log_file:
            log_file.write(f"Decryption Time for {input_file}: {decryption_time_ms:.2f} ms\n")

        # Remove the original encrypted file
        os.remove(input_file)

def main():
    key = b'\x81k\xc9k\x9b\xed/\xd5\xaf\xfc\xc81\x97\x93>\xc8:\x11n\xb3\xbc\xe3\x8d?+\xbesw\x1fof\xf1'

    encryptor = GCMEncryptor(key)

    while True:
        os.system('clear')
        print("Choose an option:")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            input_file = input("Enter the name of the file to encrypt: ")
            encryptor.encrypt_file(input_file)
            print(f"File '{input_file}' encrypted and saved as '{input_file}.enc'. Original file removed.")
        elif choice == '2':
            input_file = input("Enter the name of the encrypted file: ")
            encryptor.decrypt_file(input_file)
            print(f"File '{input_file}' decrypted and saved as '{input_file[:-4]}'. Original encrypted file removed.")
        elif choice == '3':
            exit()
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
