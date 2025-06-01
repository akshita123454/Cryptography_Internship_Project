import streamlit as st
import socket
import threading
import time
import os
import json
from p2pclient import encrypt, decrypt
from autodis import ClientDiscovery

st.set_page_config(page_title="Secure P2P Messenger", layout="centered")

st.title(" Secure P2P Messenger")
st.markdown("Send encrypted messages and files with integrity check.")

if "sock" not in st.session_state:
    st.session_state.sock = None
if "discovered" not in st.session_state:
    st.session_state.discovered = []

def start_discovery(my_port, broadcast_port):
    discovery = ClientDiscovery(my_port=my_port, broadcast_port=broadcast_port)
    threading.Thread(target=discovery.listen_for_clients, daemon=True).start()
    threading.Thread(target=discovery.broadcast_presence, daemon=True).start()
    st.session_state.discovery = discovery

def start_listener(sock, password):
    def listener():
        while True:
            data, addr = sock.recvfrom(65536)
            if data.startswith(b"msg"):
                try:
                    decrypted = decrypt(data[3:], password.encode())
                    st.session_state.chat.append(f"📩 Message from {addr[1]}: {decrypted.decode()}")
                except:
                    st.session_state.chat.append(f"❌ Message from {addr[1]}: Integrity check failed.")
            elif data.startswith(b"file"):
                try:
                    decrypted = decrypt(data[4:], password.encode())
                    filename = f"received_{addr[1]}.bin"
                    with open(filename, "wb") as f:
                        f.write(decrypted)
                    st.session_state.chat.append(f"📁 File received from {addr[1]} saved as {filename}")
                except:
                    st.session_state.chat.append(f"❌ File from {addr[1]}: Integrity check failed.")
    threading.Thread(target=listener, daemon=True).start()

with st.sidebar:
    st.header(" Configuration")
    password = st.text_input("Shared Password", type="password")
    my_port = st.number_input("Your Port", value=5001)
    peer_port = st.number_input("Peer Port", value=5002)
    broadcast_port = st.number_input("Broadcast Port", value=5002)
    if st.button("🔌 Start Service"):
        st.session_state.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        st.session_state.sock.bind(("localhost", my_port))
        st.session_state.chat = []
        start_listener(st.session_state.sock, password)
        start_discovery(my_port, broadcast_port)
        st.success("Service started!")

st.subheader(" Communication")
msg = st.text_input("Enter message")
if st.button("📨 Send Message"):
    encrypted = encrypt(msg.encode(), password.encode())
    st.session_state.sock.sendto(b"msg" + encrypted, ("localhost", peer_port))
    st.session_state.chat.append(f"📤 You to {peer_port}: {msg}")

file = st.file_uploader("📁 Choose a file to send")
if file and st.button(" Send File"):
    file_bytes = file.read()
    encrypted = encrypt(file_bytes, password.encode())
    st.session_state.sock.sendto(b"file" + encrypted, ("localhost", peer_port))
    st.session_state.chat.append(f"📤 File sent to {peer_port}: {file.name}")

st.subheader(" Chat Log")
if "chat" in st.session_state:
    for line in st.session_state.chat:
        st.text(line)

st.subheader(" Active Clients")
if "discovery" in st.session_state:
    st.session_state.discovered = st.session_state.discovery.active_clients
    for client in st.session_state.discovered:
        st.text(f"{client['host']}:{client['port']}")
else:
    st.info("Start the service to discover peers.")
