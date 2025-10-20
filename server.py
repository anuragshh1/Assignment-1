import socket
import threading

HOST = '127.0.0.1'
PORT = 65432

clients = {}   # Map username to client socket connection
public_keys = {}  # Map username to their public RSA key bytes

def handle_client(conn):
    try:
        # First receive username
        username = conn.recv(1024).decode()
        # Then receive their public key
        public_key = conn.recv(2048)
        clients[username] = conn
        public_keys[username] = public_key

        print(f"[{username}] connected and registered public key.")

        while True:
            data = conn.recv(4096)
            if not data:
                print(f"[{username}] disconnected.")
                break

            # Messages formatted as: targetusername|messagebytes
            if b'|' not in data:
                continue

            target, message = data.split(b'|', 1)
            target = target.decode()

            print(f"Encrypted message received from [{username}] to [{target}]: {message.hex()}")

            # Forward message to target if connected
            if target in clients:
                clients[target].send(message)
            else:
                print(f"Target [{target}] not connected.")
    except Exception as e:
        print(f"Exception with client {username}: {e}")
    finally:
        if username in clients:
            del clients[username]
        if username in public_keys:
            del public_keys[username]
        conn.close()

def main():
    print(f"Server starting on {HOST}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print("Server listening for connections...")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()

if __name__ == "__main__":
    main()
