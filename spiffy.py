import socket
import threading
import random
import sys

class ChatServer:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = []
        self.usernames = {}
        self.connection_code = self.generate_connection_code()
        
    def generate_connection_code(self):
        """Generate a unique 10-digit connection code"""
        return ''.join([str(random.randint(0, 9)) for _ in range(10)])
    
    def start(self):
        self.server.bind((self.host, self.port))
        self.server.listen()
        
        print("\n" + "=" * 60)
        print("    CHAT SERVER STARTED")
        print("=" * 60)
        print(f"\n📱 YOUR CONNECTION CODE: {self.connection_code}")
        print(f"\n✓ Share this 10-digit code with others to connect!")
        print(f"✓ Server running on {self.host}:{self.port}")
        print("=" * 60 + "\n")
        
        while True:
            client, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client, addr))
            thread.start()
    
    def handle_client(self, client, addr):
        try:
            # Ask for connection code
            client.send("Enter 10-digit connection code: ".encode('utf-8'))
            entered_code = client.recv(1024).decode('utf-8').strip()
            
            # Verify code
            if entered_code != self.connection_code:
                client.send("✗ INVALID CODE! Connection rejected.\n".encode('utf-8'))
                client.close()
                print(f"[REJECTED] {addr} - Wrong code entered")
                return
            
            # Ask for username
            client.send("✓ Code verified! Enter your username: ".encode('utf-8'))
            username = client.recv(1024).decode('utf-8').strip()
            
            self.usernames[client] = username
            self.clients.append(client)
            
            # Notify everyone
            join_msg = f"\n✓ {username} joined the chat!\n"
            print(f"[CONNECTED] {username} ({addr})")
            self.broadcast(join_msg, exclude=client)
            client.send(f"\n✓ Welcome {username}! You're now connected.\n".encode('utf-8'))
            
            # Receive messages
            while True:
                message = client.recv(1024).decode('utf-8')
                if message:
                    if message.strip().lower() == '/quit':
                        break
                    full_msg = f"{username}: {message}"
                    print(f"[MESSAGE] {full_msg.strip()}")
                    self.broadcast(full_msg, exclude=client)
                else:
                    break
                    
        except Exception as e:
            print(f"[ERROR] {e}")
        finally:
            self.remove_client(client)
    
    def broadcast(self, message, exclude=None):
        """Send message to all connected clients"""
        for client in self.clients:
            if client != exclude:
                try:
                    client.send(message.encode('utf-8'))
                except:
                    self.remove_client(client)
    
    def remove_client(self, client):
        """Remove client and notify others"""
        if client in self.clients:
            username = self.usernames.get(client, "Unknown")
            self.clients.remove(client)
            
            if client in self.usernames:
                del self.usernames[client]
            
            leave_msg = f"\n✗ {username} left the chat.\n"
            print(f"[DISCONNECTED] {username}")
            self.broadcast(leave_msg)
            
        client.close()


class ChatClient:
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    def connect(self):
        try:
            print("\n[CONNECTING] Attempting to connect to server...")
            self.client.connect((self.host, self.port))
            print("[CONNECTED] Successfully connected to server!\n")
            
            # Receive messages in separate thread
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Send messages from main thread
            self.send_messages()
            
        except Exception as e:
            print(f"\n[ERROR] Could not connect to server: {e}")
            print("Make sure:")
            print("  1. Server is running")
            print("  2. Server address is correct")
            print("  3. You're on the same network (if using local network)")
    
    def receive_messages(self):
        """Receive messages from server"""
        while True:
            try:
                message = self.client.recv(1024).decode('utf-8')
                if message:
                    print(message, end='')
                else:
                    break
            except:
                print("\n[DISCONNECTED] Connection to server lost.")
                self.client.close()
                sys.exit()
                break
    
    def send_messages(self):
        """Send messages to server"""
        while True:
            try:
                message = input()
                if message.strip().lower() == '/quit':
                    print("\n[EXIT] Leaving chat...")
                    self.client.send(message.encode('utf-8'))
                    self.client.close()
                    sys.exit()
                    break
                if message.strip():  # Only send non-empty messages
                    self.client.send(message.encode('utf-8'))
            except KeyboardInterrupt:
                print("\n[EXIT] Disconnecting...")
                self.client.close()
                sys.exit()
                break
            except:
                break


def main():
    print("\n" + "=" * 60)
    print("    PRIVATE TERMINAL CHAT")
    print("=" * 60)
    print("\n[1] Start Server (Get 10-digit code)")
    print("[2] Connect to Server (Enter 10-digit code)")
    print("\n" + "=" * 60)
    
    choice = input("\nYour choice: ").strip()
    
    if choice == '1':
        print("\n[SERVER MODE] Starting server...")
        server = ChatServer()
        server.start()
    
    elif choice == '2':
        print("\n[CLIENT MODE]")
        host = input("Server IP address (press Enter for 'localhost'): ").strip() or 'localhost'
        print(f"\n[INFO] Connecting to {host}:5555...")
        client = ChatClient(host=host)
        client.connect()
    
    else:
        print("\n[ERROR] Invalid choice! Please select 1 or 2.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[EXIT] Program terminated.")
        sys.exit()
