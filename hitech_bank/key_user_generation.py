from nacl.signing import SigningKey
import hashlib
import json
import os

# ===== STEP 1: Generate keys =====
private_key = SigningKey.generate()
public_key = private_key.verify_key

private_key_hex = private_key.encode().hex()
public_key_hex = public_key.encode().hex()

# ===== STEP 2: Wallet PIN =====
wallet_pin = "0726"

# Hash PIN
pin_hash = hashlib.sha256(wallet_pin.encode()).hexdigest()

# ===== STEP 3: Encrypt private key =====
def encrypt_private_key(private_key_hex, pin):
    key = hashlib.sha256(pin.encode()).digest()
    encrypted = bytes.fromhex(private_key_hex)
    encrypted_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])
    return encrypted_bytes.hex()

encrypted_private_key = encrypt_private_key(private_key_hex, wallet_pin)

# ===== STEP 4: Prepare user data =====
wallet_entry = {
    "user_id": None,  # will auto assign
    "public_key": public_key_hex,
    "encrypted_private_key": encrypted_private_key,
    "pin_hash": pin_hash
}

# ===== STEP 5: Load existing data =====
file_path = "wallet.json"

if os.path.exists(file_path):
    with open(file_path, "r") as f:
        try:
            data = json.load(f)
        except:
            data = []
else:
    data = []

# Ensure it's a list
if not isinstance(data, list):
    data = []

# Assign user_id automatically
wallet_entry["user_id"] = len(data) + 1

# Append new user
data.append(wallet_entry)

# ===== STEP 6: Save back =====
with open(file_path, "w") as f:
    json.dump(data, f, indent=4)

print("Wallet created successfully!")
print("User ID:", wallet_entry["user_id"])
print("Public Key (send to backend):", public_key_hex)