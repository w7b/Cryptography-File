import sqlite3
from cryptography.fernet import Fernet, InvalidToken
import argparse

connection = sqlite3.connect("cryptography.db")
cur = connection.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS keys (File_name TEXT, Valid_key BLOB)")

key = Fernet.generate_key()
f = Fernet(key)

def file_encrypt(args):
    try:
        with open(args.search_file, 'rb') as original_file:
            original = original_file.read()

        token = f.encrypt(original)

        with open(args.search_file, 'wb') as encrypted_file:
            encrypted_file.write(token)

        cur.execute("INSERT INTO keys (File_name, Valid_key) VALUES (?, ?)", (args.search_file, key,))
        connection.commit()
        print(f"{args.search_file} has been successfully encrypted.")
    except FileNotFoundError:
        print("File not found")
        return None
    
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def file_decryption(args):

    cur.execute("SELECT Valid_key FROM keys WHERE File_name = ?", (args.search_file,))
    result = cur.fetchone()

    if result is None:
        print(f"Key for file {args.search_file} not found.")
        return
    
    key_from_db = result[0]
    key_from_arg = args.key.encode()
    
    if key_from_db != key_from_arg:
        print("The key provided does not match the key in the database.")
        return

    f = Fernet(key_from_arg)

    try:
        with open(args.search_file, 'rb') as encrypted_file:
            encrypted = encrypted_file.read()

        decrypted = f.decrypt(encrypted)

        with open(args.search_file, 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

        print(f"File {args.search_file} successfully decrypted.")
        
        cur.execute("DELETE FROM keys WHERE File_name = ?", (args.search_file,))
        connection.commit()

    except InvalidToken:
        print("Decryption failed. The provided key is invalid or the file has been corrupted.")
    except Exception as e:
        print(f"Error {e} occurred when trying to decrypt file {args.search_file}.")

def main():

    parser = argparse.ArgumentParser(prog="Cryptography System", description="Commands: encrypt, decrypt")

    subparsers = parser.add_subparsers(dest="command", help="Encryption or decryption commands")
    
    encrypt_p = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_p.add_argument('search_file', type=str, help="Select the file to encrypt it")

    decrypt_p = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_p.add_argument('search_file', type=str, help="Select the file to decrypt")
    decrypt_p.add_argument('key', type=str, help="Provide the key to decrypt the file")

    args = parser.parse_args()

    if args.command == "encrypt":
        file_encrypt(args)
    elif args.command == "decrypt":
        file_decryption(args)

if __name__ == "__main__":
    main()