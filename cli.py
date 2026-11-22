import argparse
from pathlib import Path
from core import *

def main():
    alice_priv, alice_pub, bob_priv, bob_pub = load_or_generate_keys()
    users = {"Alice": (alice_priv, alice_pub), "Bob": (bob_priv, bob_pub)}

    parser = argparse.ArgumentParser(description="Enigma + RSA CLI Chat")
    parser.add_argument("--from", dest="sender", required=True, choices=["Alice", "Bob"])
    parser.add_argument("--to", dest="receiver", required=True, choices=["Alice", "Bob"])
    parser.add_argument("--message", required=True, help="Message to encrypt and send")
    parser.add_argument("--rotors", default="I II III")
    parser.add_argument("--reflector", default="B")
    parser.add_argument("--ring", default="01 01 01")
    parser.add_argument("--plugboard", default="AB CD EF")
    parser.add_argument("--pos", default="AAA")
    parser.add_argument("--attach", nargs='*', help="List of files to attach")
    parser.add_argument("--show-thread", action="store_true")

    args = parser.parse_args()
    if args.sender == args.receiver:
        print("❌ Sender and receiver must differ.")
        return

    sender_priv = users[args.sender][0]
    receiver_pub = users[args.receiver][1]
    config = (args.rotors, args.reflector, args.ring, args.plugboard, args.pos)

    attachments = []
    if args.attach:
        for path in args.attach:
            file_path = Path(path)
            if file_path.exists():
                attachments.append((file_path.name, file_path.read_bytes()))
            else:
                print(f"❌ File not found: {file_path}")
                return

    bundle = send_message(sender_priv, receiver_pub, args.message, config, attachments)
    bundle["from"] = args.sender
    bundle["to"] = args.receiver
    append_to_thread(bundle)
    print(f"✅ Sent message from {args.sender} to {args.receiver}.")

    if args.show_thread:
        thread = load_thread()["thread"]
        for i, entry in enumerate(thread):
            sender = entry["from"]
            receiver = entry["to"]
            msg, valid, cfg, files = receive_message(users[receiver][0], users[sender][1], entry)
            print(f"\n#{i+1}: {sender} → {receiver} at {entry['timestamp']}")
            print(f"   Encrypted: {entry['encrypted_message']}")
            print(f"   Decrypted: {msg}")
            print(f"   Signature: {'✅ Valid' if valid else '❌ Invalid'}")
            if files:
                for fname, data in files:
                    out_path = Path(f"received_{fname}")
                    out_path.write_bytes(data)
                    print(f"   📎 Saved attachment: {out_path}")

if __name__ == "__main__":
    main()