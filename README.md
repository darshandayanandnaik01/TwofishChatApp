# TwofishChatApp
Secure Python chat app using AES-256-GCM encryption and Flask-SocketIO — by Darshan.


# 🔐 TwofishChat — Encrypted Chat Application  
### Developed by **Darshan

A **secure Python chat app** using **AES-256-GCM** encryption and **Flask-SocketIO** for real-time, end-to-end encrypted communication.  
Messages are protected using a secure **X25519 key exchange** with automatic handshake.  

---

## 🧠 Description
**Secure Python chat app using AES-256-GCM encryption and Flask-SocketIO — by Darshan.**

---

## 🚀 Features
- ✅ Real-time encrypted chat between multiple clients  
- ✅ End-to-end encryption with AES-256-GCM  
- ✅ Automatic X25519 key exchange (no manual key setup)  
- ✅ Simple and lightweight command-line interface  
- ✅ Tested, stable, and error-free  

---

## ⚙️ Requirements

Make sure you have **Python 3.10+** installed.

Install required libraries:
```bash
pip install flask flask-socketio "python-socketio[client]" cryptography pycryptodome


🖥️ How to Run This Project
🪜 Step 1 — Open your project folder
cd C:\Users\Darshan\TwofishChat

🪜 Step 2 — Activate the virtual environment
& .venv\Scripts\Activate.ps1

🪜 Step 3 — Start the server
python server.py


Keep this window open — it’s your central chat server.

🪜 Step 4 — Start Client 1 (Alice)

Open a new terminal and run:

& .venv\Scripts\Activate.ps1
python client.py alice

🪜 Step 5 — Start Client 2 (Bob)

Open another new terminal and run:

& .venv\Scripts\Activate.ps1
python client.py bob

💬 Chat Commands

After both clients are connected, use these commands to chat:

On Alice’s terminal:
/msg bob Hello Bob!

On Bob’s terminal:
/msg alice Hi Alice!


✅ Expected output:

[alice] Hello Bob!
[bob] Hi Alice!


To exit any client:

/exit


To stop the server:

CTRL + C

🧱 Folder Structure
TwofishChat/
│
├── client.py        # Client-side encryption, key exchange, messaging
├── server.py        # Flask-SocketIO server for message relay
├── .gitignore       # Ignore venv and cache files
└── README.md        # Project information and usage guide
