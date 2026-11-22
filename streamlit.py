import streamlit as st
import json
from core import *

def main():
    st.set_page_config("Enigma+RSA Chat", layout="centered")
    st.title("🔐 Enigma + RSA Chat")

    alice_priv, alice_pub, bob_priv, bob_pub = load_or_generate_keys()
    users = {"Alice": (alice_priv, alice_pub), "Bob": (bob_priv, bob_pub)}

    st.sidebar.header("🔑 RSA Keys")
    if st.sidebar.checkbox("Show Alice Public Key"):
        st.sidebar.code(alice_pub.export_key().decode())
    if st.sidebar.checkbox("Show Bob Public Key"):
        st.sidebar.code(bob_pub.export_key().decode())

    user = st.selectbox("Sender", ["Alice", "Bob"])
    recipient = "Bob" if user == "Alice" else "Alice"
    st.subheader(f"✉️ {user} → {recipient}")

    with st.expander("🔧 Enigma Settings", expanded=True):
        rotors = st.text_input("Rotors", "I II III")
        reflector = st.text_input("Reflector", "B")
        ring = st.text_input("Ring Settings", "01 01 01")
        plugboard = st.text_input("Plugboard", "AB CD EF")
        pos = st.text_input("Initial Position", "AAA")

    msg = st.text_area("Message:")
    uploaded_files = st.file_uploader("📎 Attach files", accept_multiple_files=True)

    if st.button("Send"):
        attachments = [(f.name, f.read()) for f in uploaded_files] if uploaded_files else None
        bundle = send_message(users[user][0], users[recipient][1], msg, (rotors, reflector, ring, plugboard, pos), attachments)
        bundle["from"], bundle["to"] = user, recipient
        append_to_thread(bundle)
        st.success("Message sent!")

    st.subheader("📜 Thread")
    thread = load_thread()["thread"]
    if not thread:
        st.info("No messages yet.")
    else:
        for i, entry in enumerate(reversed(thread)):
            sender, receiver = entry["from"], entry["to"]
            timestamp = entry["timestamp"]
            msg, valid, cfg, attachments = receive_message(users[receiver][0], users[sender][1], entry)
            with st.expander(f"#{len(thread)-i}: {sender} → {receiver} @ {timestamp}"):
                st.markdown(f"**Encrypted:** `{entry['encrypted_message']}`")
                st.success(f"Decrypted: {msg}")
                st.markdown(f"Signature: {'✅ Valid' if valid else '❌ Invalid'}")
                st.code(cfg)
                if attachments:
                    st.markdown("📎 Attachments:")
                    for fname, data in attachments:
                        st.download_button(f"Download {fname}", data, file_name=fname)

if __name__ == "__main__":
    main()