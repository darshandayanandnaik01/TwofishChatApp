# client.py — Final Stable Version (AES-256-GCM Encrypted Chat)
import base64
import sys
import socketio
import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

# ==========================================================
# CONFIGURATION
# ==========================================================
SERVER_URL = 'http://localhost:5000'

sio = socketio.Client()
peer_shared_keys = {}   # peer -> AES-256 key
local_ephemeral = {}    # peer -> X25519PrivateKey
pending_pubkeys = {}    # peer -> bool

# ==========================================================
# HELPER FUNCTIONS
# ==========================================================
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def derive_key(shared_secret: bytes, info: bytes = b'handshake aes-gcm chat') -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared_secret)

def aesgcm_encrypt(key: bytes, plaintext: bytes):
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ct, tag

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def ts():
    """Timestamp for UI."""
    return datetime.datetime.now().strftime("%H:%M:%S")

# ==========================================================
# SOCKET.IO HANDLERS
# ==========================================================
@sio.event
def connect():
    print("[*] Connected to server.")

@sio.on('registered')
def on_registered(_):
    print("[*] Registered OK.")
    print("Commands:")
    print("  /msg <peer> <message>")
    print("  /exit")
    print("> ", end="", flush=True)

@sio.on('handshake')
def on_handshake(data):
    sender = data.get('from')
    their_pk_b64 = data.get('pubkey')
    if not sender or not their_pk_b64:
        return

    their_pk = ub64(their_pk_b64)
    print(f"\n[{ts()}] [handshake] Received public key from {sender}")

    # --- FIXED: Always reuse the same private key for a given peer ---
    if sender in local_ephemeral:
        priv = local_ephemeral[sender]
    else:
        priv = x25519.X25519PrivateKey.generate()
        local_ephemeral[sender] = priv

    peer_pub = x25519.X25519PublicKey.from_public_bytes(their_pk)
    shared = priv.exchange(peer_pub)
    key = derive_key(shared)
    peer_shared_keys[sender] = key

    print(f"[{ts()}] [handshake] Derived AES-256-GCM key for {sender}.")

    # Auto-reply with our public key if needed
    if sender not in pending_pubkeys:
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        sio.emit('handshake', {'to': sender, 'from': username, 'pubkey': b64(pub)})
        pending_pubkeys[sender] = True
        print(f"[{ts()}] [handshake] Auto-replied to {sender}")

    print("> ", end="", flush=True)

@sio.on('message')
def on_message(data):
    sender = data.get('from')
    payload = data.get('payload')
    if not sender or not payload:
        return

    if sender not in peer_shared_keys:
        print(f"[!] No shared key for {sender}.")
        return

    key = peer_shared_keys[sender]
    nonce = ub64(payload['nonce'])
    ct = ub64(payload['ciphertext'])
    tag = ub64(payload['tag'])

    try:
        pt = aesgcm_decrypt(key, nonce, ct, tag)
        print(f"\n[{ts()}] [{sender}] {pt.decode()}")
    except Exception as e:
        print(f"[!] Decryption failed: {e}")

    sys.stdout.flush()
    print("> ", end="", flush=True)

# ==========================================================
# CLIENT ACTIONS
# ==========================================================
def register(user):
    sio.emit('register', {'username': user})

def send_handshake(to, me):
    if to not in local_ephemeral:
        priv = x25519.X25519PrivateKey.generate()
        local_ephemeral[to] = priv
    priv = local_ephemeral[to]
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    sio.emit('handshake', {'to': to, 'from': me, 'pubkey': b64(pub)})
    print(f"[{ts()}] [handshake] Sent handshake to {to}")

def send_message(to, me, text):
    if to not in peer_shared_keys:
        print(f"[{ts()}] [handshake] No shared key with {to}. Initiating handshake...")
        send_handshake(to, me)
        return

    key = peer_shared_keys[to]
    nonce, ct, tag = aesgcm_encrypt(key, text.encode())
    sio.emit('message', {
        'to': to,
        'from': me,
        'payload': {
            'nonce': b64(nonce),
            'ciphertext': b64(ct),
            'tag': b64(tag)
        }
    })
    print(f"[{ts()}] [you -> {to}] {text}")

# ==========================================================
# COMMAND LOOP
# ==========================================================
def repl_loop(me):
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        # Ignore empty lines or stray incoming messages
        if not line or line.startswith('['):
            continue

        if line.startswith('/msg'):
            parts = line.split(maxsplit=2)
            if len(parts) < 3:
                print("Usage: /msg <peer> <message>")
                continue
            send_message(parts[1], me, parts[2])

        elif line.startswith('/exit'):
            sio.disconnect()
            break

        else:
            print("Unknown command. Use /msg or /exit.")

# ==========================================================
# MAIN
# ==========================================================
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python client.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    sio.connect(SERVER_URL)
    register(username)
    repl_loop(username)
