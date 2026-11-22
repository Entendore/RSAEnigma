import streamlit as st
import string
import base64
import json
from datetime import datetime
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from enigma.machine import EnigmaMachine

# --- Paths ---
KEY_DIR = Path("keys")
THREAD_FILE = Path("chat_thread.json")

# --- RSA key file helpers ---
def save_rsa_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.export_key())

def load_rsa_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def generate_and_save_keys():
    KEY_DIR.mkdir(exist_ok=True)
    alice_priv = RSA.generate(2048)
    alice_pub = alice_priv.publickey()
    bob_priv = RSA.generate(2048)
    bob_pub = bob_priv.publickey()

    save_rsa_key(alice_priv, KEY_DIR / "alice_private.pem")
    save_rsa_key(alice_pub,  KEY_DIR / "alice_public.pem")
    save_rsa_key(bob_priv,   KEY_DIR / "bob_private.pem")
    save_rsa_key(bob_pub,    KEY_DIR / "bob_public.pem")

    return alice_priv, alice_pub, bob_priv, bob_pub

# --- Load or generate keys ---
def load_or_generate_keys():
    try:
        alice_priv = load_rsa_key(KEY_DIR / "alice_private.pem")
        alice_pub = load_rsa_key(KEY_DIR / "alice_public.pem")
        bob_priv = load_rsa_key(KEY_DIR / "bob_private.pem")
        bob_pub = load_rsa_key(KEY_DIR / "bob_public.pem")
        return alice_priv, alice_pub, bob_priv, bob_pub
    except FileNotFoundError:
        return generate_and_save_keys()

# --- RSA functions ---
def rsa_encrypt(pubkey, plaintext: str) -> bytes:
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(plaintext.encode())

def rsa_decrypt(privkey, ciphertext: bytes) -> str:
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext).decode()

def sign_message(privkey, message: str) -> bytes:
    h = SHA256.new(message.encode())
    signer = pkcs1_15.new(privkey)
    return signer.sign(h)

def verify_signature(pubkey, message: str, signature: bytes) -> bool:
    h = SHA256.new(message.encode())
    verifier = pkcs1_15.new(pubkey)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- Enigma helpers ---
def make_enigma(rotors, reflector, ring_settings, plugboard, initial_pos):
    machine = EnigmaMachine.from_key_sheet(
        rotors=rotors,
        reflector=reflector,
        ring_settings=ring_settings,
        plugboard_settings=plugboard
    )
    machine.set_display(initial_pos)
    return machine

# --- Send and receive messages ---
def send_message(sender_priv, receiver_pub, message, enigma_config):
    machine = make_enigma(*enigma_config)
    encrypted_msg = machine.process_text(message)
    signature = sign_message(sender_priv, encrypted_msg)
    config_str = '|'.join(enigma_config)
    encrypted_key = rsa_encrypt(receiver_pub, config_str)
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "encrypted_message": encrypted_msg,
        "signature": base64.b64encode(signature).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }

def receive_message(receiver_priv, sender_pub, bundle):
    encrypted_msg = bundle["encrypted_message"]
    signature = base64.b64decode(bundle["signature"])
    encrypted_key = base64.b64decode(bundle["encrypted_key"])
    enigma_config_str = rsa_decrypt(receiver_priv, encrypted_key)
    rotors, reflector, ring_settings, plugboard, initial_pos = enigma_config_str.split('|')
    valid = verify_signature(sender_pub, encrypted_msg, signature)
    machine = make_enigma(rotors, reflector, ring_settings, plugboard, initial_pos)
    decrypted_msg = machine.process_text(encrypted_msg)
    return decrypted_msg, valid, (rotors, reflector, ring_settings, plugboard, initial_pos)

# --- Chat thread file ---
def load_thread():
    if THREAD_FILE.exists():
        with open(THREAD_FILE, "r") as f:
            return json.load(f)
    return {"thread": []}

def save_thread(thread):
    with open(THREAD_FILE, "w") as f:
        json.dump(thread, f, indent=2)

def append_to_thread(message_entry):
    thread = load_thread()
    thread["thread"].append(message_entry)
    save_thread(thread)

# --- Streamlit UI ---
def main():
    st.title("🔐 Enigma + RSA Hybrid Chat with File Persistence")

    alice_priv, alice_pub, bob_priv, bob_pub = load_or_generate_keys()
    known_users = {
        "Alice": (alice_priv, alice_pub),
        "Bob": (bob_priv, bob_pub)
    }

    # Sidebar info
    st.sidebar.header("User Keys")
    if st.sidebar.checkbox("Show Alice Public Key"):
        st.sidebar.code(alice_pub.export_key().decode(), language="pem")
    if st.sidebar.checkbox("Show Bob Public Key"):
        st.sidebar.code(bob_pub.export_key().decode(), language="pem")

    # Select user and recipient
    user = st.selectbox("Select user (sender):", ["Alice", "Bob"])
    recipient = "Bob" if user == "Alice" else "Alice"

    st.subheader(f"Send message as {user} → {recipient}")

    # Enigma config input (real Enigma rotors etc)
    with st.expander("Configure Enigma Settings"):
        rotors = st.text_input("Rotors (space separated, e.g. I II III)", value="I II III")
        reflector = st.text_input("Reflector (e.g. B)", value="B")
        ring_settings = st.text_input("Ring Settings (space separated, e.g. 01 01 01)", value="01 01 01")
        plugboard = st.text_input("Plugboard pairs (space separated, e.g. AB CD EF)", value="AB CD EF")
        initial_pos = st.text_input("Initial Rotor Positions (e.g. AAA)", value="AAA")

    message = st.text_area("Message to encrypt:")

    if st.button("Send Message"):
        if not message.strip():
            st.warning("Enter a message!")
        else:
            sender_priv = known_users[user][0]
            receiver_pub = known_users[recipient][1]
            enigma_config = (rotors, reflector, ring_settings, plugboard, initial_pos)
            bundle = send_message(sender_priv, receiver_pub, message, enigma_config)

            # Add metadata
            bundle["from"] = user
            bundle["to"] = recipient
            append_to_thread(bundle)
            st.success(f"Message sent from {user} to {recipient}!")

    # Show conversation thread
    st.subheader("Message Thread")
    thread = load_thread()["thread"]

    if not thread:
        st.info("No messages yet.")
    else:
        for i, entry in enumerate(thread):
            sender = entry["from"]
            receiver = entry["to"]
            timestamp = entry["timestamp"]
            sender_pub = known_users[sender][1]
            receiver_priv = known_users[receiver][0]

            decrypted, valid, enigma_conf = receive_message(receiver_priv, sender_pub, entry)

            with st.expander(f"Message #{i+1} from {sender} to {receiver} at {timestamp}"):
                st.write(f"**Encrypted Message:** `{entry['encrypted_message']}`")
                st.write(f"**Decrypted Message:** {decrypted}")
                st.write(f"**Signature Valid:** {'✅' if valid else '❌'}")
                st.write(f"**Enigma Config:** {enigma_conf}")

    # Export chat button
    if st.button("Export Chat Thread to JSON"):
        thread_json = json.dumps(thread, indent=2)
        st.download_button("Download Chat JSON", thread_json, file_name="chat_thread.json")

if __name__ == "__main__":
    main()
