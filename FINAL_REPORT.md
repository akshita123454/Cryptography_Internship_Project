Progress Report: Secure P2P Chat Application – Phase II
Submitted to: [DRDO Scientist Name]
Submitted by: Ayush Kumar
Reporting Period: Day 29 to Day 42
Project Title: Development of Secure Peer-to-Peer Communication Application

Objectives for This Period
Following the successful completion of cryptographic and networking backend (AES, RSA, SHA, peer discovery), the goal for this development sprint was to:
- Design and implement a robust, user-friendly GUI using Tkinter (migrated from Streamlit).
- Integrate peer-to-peer encrypted messaging and file transfer into the GUI.
- Ensure secure key exchange, message integrity, and encrypted file transfer in the user-facing version.
- Improve code modularity and UX for future scalability.

Key Features Implemented
1. Tkinter-based Graphical User Interface
- Developed a modern, dark-themed chat interface allowing:
  - Entry of shared password, peer IP/port, and local port
  - Real-time chat log and file transfer status
  - Peer discovery and dynamic peer list via UDP broadcast
  - File dialog for easy file selection and sending
- GUI is tightly integrated with cryptographic and networking backends

2. Encrypted Messaging and File Transfer (AES & RSA)
- Messages and files are encrypted using AES-256 in CBC mode with random IV and salt.
- HMAC-SHA256 is used for message and file integrity (tag verified before decryption).
- Each peer generates an ephemeral 2048-bit RSA key pair at startup.
- Public keys are exchanged at session start; session keys can be encrypted with the peer's public key for forward secrecy.
- Files are split into 1024-byte chunks, each chunk encrypted and HMAC-protected, then reassembled on the receiver side.

3. Message and File Integrity with HMAC (SHA-256)
- Every outgoing message and file chunk includes a SHA-256-based HMAC tag.
- Receiver validates the HMAC before accepting and decrypting the data.

4. Auto-Discovery of Peers via UDP Broadcast
- Implemented a background UDP listener that:
  - Periodically broadcasts the user's port and presence
  - Listens for other clients on the same local network
  - Dynamically updates the discovered peer list in the GUI

Challenges Faced
- GUI Real-Time Handling: Tkinter threading and socket integration required careful management to avoid blocking the UI.
- Chunked File Transfer: Ensured reliable reassembly and integrity verification of files sent over UDP.
- Key Management: Used PEM serialization for secure public key exchange.
- Auto-discovery: Managed port contention and deduplication of discovered peers.

Improvements Made
- Modular codebase with clear separation between GUI, encryption, networking, and discovery.
- Error handling for malformed packets, failed decryption, and missing keys.
- GUI UX improved with real-time status updates and error banners.
- Secure file transfer with chunking and HMAC integrity is now fully implemented.

Current Output / Deliverables
- app_final_version.py: Tkinter GUI application (main entry point)
- gui_for_p2p/: Supporting modules for GUI and cryptography
  - autodis.py, gui.py, p2pclient.py, rsa.py
- Auto discovery.py: Standalone peer discovery script
- p2pclient.py: Core P2P communication logic
- RSA Algorithm.py: RSA cryptography utilities
- README.md: Project documentation

Conclusion
This reporting period focused on converting backend cryptographic tools into a robust, user-friendly peer-to-peer chat and file transfer application. The new Tkinter GUI enables encrypted and integrity-checked messaging and file transfer between dynamically discovered peers. The system now supports chunked, encrypted file transfer with HMAC-based integrity, providing a comprehensive demonstration of secure P2P communication on local networks.

