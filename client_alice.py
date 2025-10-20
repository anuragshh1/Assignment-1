import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import json
from datetime import datetime
import os

HOST = '127.0.0.1'
PORT = 65432
USERNAME = 'alice'
TARGET = 'bob'

def generate_keys():
    priv = f"{USERNAME}_private.pem"
    pub = f"{USERNAME}_public.pem"
    if not (os.path.exists(priv) and os.path.exists(pub)):
        key = RSA.generate(2048)
        with open(priv, "wb") as f:
            f.write(key.export_key())
        with open(pub, "wb") as f:
            f.write(key.publickey().export_key())
        print(f"Generated RSA keys for {USERNAME}")
    else:
        print(f"RSA keys for {USERNAME} already exist")

def load_keys():
    with open(f"{USERNAME}_private.pem", "rb") as f:
        priv = RSA.import_key(f.read())
    with open(f"{USERNAME}_public.pem", "rb") as f:
        pub = RSA.import_key(f.read())
    return priv, pub

def load_target_public_key():
    filename = f"{TARGET}_public.pem"
    if not os.path.exists(filename):
        raise FileNotFoundError(f"{filename} not found. Please ensure {TARGET}'s public key file is available.")
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def log_message(ciphertext, plaintext):
    entry = {
        "time": datetime.now().isoformat(),
        "ciphertext": ciphertext.hex(),
        "plaintext": plaintext
    }
    try:
        with open("messages.json", "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = []
    data.append(entry)
    with open("messages.json", "w") as f:
        json.dump(data, f, indent=4)

def main():
    generate_keys()
    private_key, public_key = load_keys()
    bob_public_key = load_target_public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(USERNAME.encode())
        s.sendall(public_key.export_key())
        print(f"Registered {USERNAME} and public key with server.")

        session_key = get_random_bytes(16)
        cipher_rsa = PKCS1_OAEP.new(bob_public_key)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        s.sendall(f"{TARGET}|".encode() + encrypted_session_key)
        print("Sent encrypted AES session key to Bob.")

        while True:
            message = input(f"{USERNAME} > ")
            if message.lower() == "exit":
                print("Exiting.")
                break
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
            encrypted_msg = cipher_aes.nonce + b"|" + tag + b"|" + ciphertext
            s.sendall(f"{TARGET}|".encode() + encrypted_msg)
            log_message(ciphertext, message)

if __name__ == "__main__":
    main()

