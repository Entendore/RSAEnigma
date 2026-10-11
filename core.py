import base64, json
from datetime import datetime
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from enigma.machine import EnigmaMachine

KEY_DIR = Path("keys")
THREAD_FILE = Path("chat_thread.json")

def save_rsa_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.export_key())

def load_rsa_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def generate_and_save_keys():
    KEY_DIR.mkdir(exist_ok=True)
    alice_priv = RSA.generate(2048)
    bob_priv = RSA.generate(2044)
    save_rsa_key(alice_priv, KEY_DIR / "alice_private.pem")
    save_rsa_key(alice_priv.publickey(), KEY_DIR / "alice_public.pem")
    save_rsa_key(bob_priv, KEY_DIR / "bob_private.pem")
    save_rsa_key(bob_priv.publickey(), KEY_DIR / "bob_public.pem")
    return alice_priv, alice_priv.publickey(), bob_priv, bob_priv.publickey()

def load_or_generate_keys():
    try:
        return (
            load_rsa_key(KEY_DIR / "alice_private.pem"),
            load_rsa_key(KEY_DIR / "alice_public.pem"),
            load_rsa_key(KEY_DIR / "bob_private.pem"),
            load_rsa_key(KEY_DIR / "bob_public.pem"),
        )
    except FileNotFoundError:
        return generate_and_save_keys()

def rsa_encrypt(pubkey, plaintext: str) -> bytes:
    return PKCS1_OAEP.new(pubkey).encrypt(plaintext.encode())

def rsa_decrypt(privkey, ciphertext: bytes) -> str:
    return PKCS1_OAEP.new(privkey).decrypt(ciphertext).decode()

def sign_message(privkey, message: str) -> bytes:
    h = SHA256.new(message.encode())
    return pkcs1_15.new(privkey).sign(h)

def verify_signature(pubkey, message: str, signature: bytes) -> bool:
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def make_enigma(rotors, reflector, ring_settings, plugboard, initial_pos):
    ring_settings = [int(r.lstrip("0") or "0") for r in ring_settings.split()]
    machine = EnigmaMachine.from_key_sheet(
        rotors=rotors.split(),
        reflector=reflector,
        ring_settings=ring_settings,
        plugboard_settings=plugboard
    )
    machine.set_display(initial_pos)
    return machine

def encrypt_attachments(files, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    result = []
    for name, data in files:
        encrypted = cipher.encrypt(data)
        result.append({
            "filename": name,
            "encrypted_data": base64.b64encode(encrypted).decode()
        })
    return result

def decrypt_attachments(enc_files, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    result = []
    for entry in enc_files:
        raw = base64.b64decode(entry["encrypted_data"])
        decrypted = cipher.decrypt(raw)
        result.append((entry["filename"], decrypted))
    return result

def send_message(sender_priv, receiver_pub, message, enigma_config, attachments=None):
    machine = make_enigma(*enigma_config)
    encrypted_msg = machine.process_text(message)
    signature = sign_message(sender_priv, encrypted_msg)
    config_str = '|'.join(enigma_config)
    encrypted_key = rsa_encrypt(receiver_pub, config_str)

    result = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "encrypted_message": encrypted_msg,
        "signature": base64.b64encode(signature).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode()
    }

    if attachments:
        result["attachments"] = encrypt_attachments(attachments, receiver_pub)

    return result

def receive_message(receiver_priv, sender_pub, bundle):
    encrypted_msg = bundle["encrypted_message"]
    signature = base64.b64decode(bundle["signature"])
    encrypted_key = base64.b64decode(bundle["encrypted_key"])
    config_str = rsa_decrypt(receiver_priv, encrypted_key)
    rotors, reflector, ring, plugboard, pos = config_str.split('|')
    valid = verify_signature(sender_pub, encrypted_msg, signature)
    machine = make_enigma(rotors, reflector, ring, plugboard, pos)
    decrypted_msg = machine.process_text(encrypted_msg)

    attachments = []
    if "attachments" in bundle:
        attachments = decrypt_attachments(bundle["attachments"], receiver_priv)

    return decrypted_msg, valid, (rotors, reflector, ring, plugboard, pos), attachments

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