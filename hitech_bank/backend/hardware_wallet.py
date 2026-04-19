import hashlib
import json
import os
from nacl.signing import SigningKey

WALLET_PATH = os.path.join(os.path.dirname(__file__), "../wallet_store/wallet.json")


def canonical_amount_str(amount):
    """Same string for signing and server-side message rebuild (matches generate_transactions.py style)."""
    if amount is None:
        return "0"
    f = float(amount)
    if f == int(f):
        return str(int(f))
    return str(f)


def load_wallet():
    """Load wallet.json"""
    if not os.path.exists(WALLET_PATH):
        return []
    with open(WALLET_PATH, "r") as f:
        return json.load(f)


def save_wallet(data):
    """Save wallet.json"""
    with open(WALLET_PATH, "w") as f:
        json.dump(data, f, indent=4)


def verify_wallet_pin(user_id, pin):
    """Verify wallet PIN against stored hash"""
    wallet = load_wallet()
    user = next((u for u in wallet if u["user_id"] == user_id), None)
    if not user:
        return False
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    return user["pin_hash"] == pin_hash


def decrypt_private_key(encrypted_hex, pin):
    """XOR-decrypt private key with pin-derived key"""
    key = hashlib.sha256(pin.encode()).digest()
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_bytes)])
    return decrypted.hex()


def sign_transaction(private_key_hex, message):
    """Sign message using EdDSA"""
    signing_key = SigningKey(bytes.fromhex(private_key_hex))
    return signing_key.sign(message.encode()).signature.hex()


def sign_with_wallet(user_id, pin, sender_id, receiver_id, amount, tx_index=0):
    """Full signing flow: load wallet, decrypt key, sign"""
    wallet = load_wallet()
    user = next((u for u in wallet if u["user_id"] == user_id), None)
    if not user:
        return None, "User not found in wallet"

    # Verify PIN
    pin_hash = hashlib.sha256(pin.encode()).hexdigest()
    if user["pin_hash"] != pin_hash:
        return None, "Invalid wallet PIN"

    # Decrypt private key
    private_key_hex = decrypt_private_key(user["encrypted_private_key"], pin)

    # Create message (must match verify.build_transaction_sign_message on backend)
    message = (
        f"{int(sender_id)}->{int(receiver_id)}:"
        f"{canonical_amount_str(amount)}:{int(tx_index)}"
    )

    # Sign
    signature = sign_transaction(private_key_hex, message)

    return {"signature": signature, "message": message}, None


def generate_and_store_keys(user_id, pin="0726"):
    """Generate new keypair and store in wallet.json"""
    wallet = load_wallet()

    private_key = SigningKey.generate()
    public_key = private_key.verify_key
    private_key_hex = private_key.encode().hex()
    public_key_hex = public_key.encode().hex()

    pin_hash = hashlib.sha256(pin.encode()).hexdigest()

    key = hashlib.sha256(pin.encode()).digest()
    encrypted = bytes.fromhex(private_key_hex)
    encrypted_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted)])
    encrypted_private_key = encrypted_bytes.hex()

    entry = {
        "user_id": user_id,
        "public_key": public_key_hex,
        "encrypted_private_key": encrypted_private_key,
        "pin_hash": pin_hash
    }

    # Remove existing entry if any
    wallet = [u for u in wallet if u["user_id"] != user_id]
    wallet.append(entry)
    save_wallet(wallet)

    return public_key_hex
