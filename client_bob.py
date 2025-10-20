import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import json
from datetime import datetime
import os

HOST = '127.0.0.1'
PORT = 65432
USERNAME = 'bob'
session_key = None

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
    global session_key
    generate_keys()
    private_key, public_key = load_keys()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(USERNAME.encode())
        s.sendall(public_key.export_key())
        print("Registered and waiting for encrypted AES session key and messages...")

        while True:
            data = s.recv(4096)
            if not data:
                print("Connection closed.")
                break

            if session_key is None:
                try:
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    session_key = cipher_rsa.decrypt(data)
                    print("AES session key received and decrypted.")
                except Exception as e:
                    print(f"Failed decrypting session key: {e}")
            else:
                try:
                    nonce, tag, ciphertext = data.split(b"|")
                    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
                    print(f"\n[Encrypted]: {ciphertext.hex()}")
                    print(f"[Decrypted]: {plaintext}\n")
                    log_message(ciphertext, plaintext)
                except Exception as e:
                    print(f"Decryption error or message tampered: {e}")

if __name__ == "__main__":
    main()
