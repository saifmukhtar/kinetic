#!/usr/bin/env python3
import argparse
import sys

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("Error: The 'cryptography' library is not installed.")
    print("Please install it using: pip install cryptography")
    sys.exit(1)

def generate_key():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    print(f"Private Key (hex): {priv_bytes.hex()}")
    print(f"Public Key (hex):  {pub_bytes.hex()}")
    print("\n[!] Put the Public Key inside atlas.json's 'updater_public_key' field.")
    print("[!] Keep the Private Key secret and use it to sign future updates.")

def sign_file(private_key_hex, file_path):
    try:
        priv_bytes = bytes.fromhex(private_key_hex)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        sys.exit(1)

    signature = private_key.sign(data)
    sig_hex = signature.hex()
    
    sig_path = file_path + ".sig"
    try:
        with open(sig_path, 'w') as f:
            f.write(sig_hex)
    except Exception as e:
        print(f"Error writing {sig_path}: {e}")
        sys.exit(1)
    
    print(f"Successfully signed {file_path}")
    print(f"Signature written to {sig_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Atlas Auto-Updater Cryptographic Signer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    gen_parser = subparsers.add_parser("generate", help="Generate a new Ed25519 keypair")
    
    sign_parser = subparsers.add_parser("sign", help="Sign a JSON file")
    sign_parser.add_argument("private_key_hex", help="Your private key in hex format")
    sign_parser.add_argument("file_path", help="Path to the .json file to sign")
    
    args = parser.parse_args()
    
    if args.command == "generate":
        generate_key()
    elif args.command == "sign":
        sign_file(args.private_key_hex, args.file_path)
