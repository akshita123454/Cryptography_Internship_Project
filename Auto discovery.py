import socket
import threading
import json
import time

class ClientDiscovery:
    def __init__(self, bind_port, broadcast_port=5002):
        self.broadcast_port = broadcast_port
        self.active_clients = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', bind_port))

    def broadcast_presence(self, host, port):
        message = json.dumps({"host": host, "port": port}).encode()
        while True:
            self.sock.sendto(message, ('255.255.255.255', self.broadcast_port))
            time.sleep(5)

    def listen_for_clients(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            client_info = json.loads(data.decode())
            if client_info not in self.active_clients:
                self.active_clients.append(client_info)
                print(f"[Client 2] Discovered client: {client_info}")

if __name__ == "__main__":
    discovery = ClientDiscovery(bind_port=5002, broadcast_port=5002)
    threading.Thread(target=discovery.listen_for_clients, daemon=True).start()
    threading.Thread(target=discovery.broadcast_presence, args=('127.0.0.1', 5000), daemon=True).start()

    while True:
        time.sleep(1)
