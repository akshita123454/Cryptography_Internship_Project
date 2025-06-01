import socket
import threading
import json
import time


class ClientDiscovery:
    def __init__(self, my_port, broadcast_port):
        self.my_port = my_port
        self.broadcast_port = broadcast_port
        self.active_clients = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', self.my_port))

    def broadcast_presence(self):
        message = json.dumps({
            "host": "127.0.0.1",
            "port": self.my_port
        }).encode()

        while True:
            self.sock.sendto(message, ('255.255.255.255', self.broadcast_port))
            print(f"[INFO] Broadcasting presence from port {self.my_port}...")
            time.sleep(5)

    def listen_for_clients(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(1024)
                client_info = json.loads(data.decode())

                if client_info["port"] != self.my_port and client_info not in self.active_clients:
                    self.active_clients.append(client_info)
                    print(f"[DISCOVERED] Client discovered: {client_info}")
            except Exception as e:
                print(f"[ERROR] Failed to process client data: {e}")


def main():
    print("=== Auto-Discovery of Active Clients (Network Programming) ===")
    my_port = int(input("Enter your port number (e.g., 5001): "))
    broadcast_port = int(input("Enter broadcast port number (e.g., 5002): "))

    discovery = ClientDiscovery(my_port=my_port, broadcast_port=broadcast_port)

    listener_thread = threading.Thread(target=discovery.listen_for_clients, daemon=True)
    broadcaster_thread = threading.Thread(target=discovery.broadcast_presence, daemon=True)

    listener_thread.start()
    broadcaster_thread.start()

    print(f"\n[STARTED] Auto-discovery service running on port {my_port}...\nPress Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[EXIT] Shutting down discovery service.")


if __name__ == "__main__":
    main()
