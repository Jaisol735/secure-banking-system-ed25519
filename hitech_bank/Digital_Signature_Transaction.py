"""
Digital signature helpers (reference / mirror of production backend).

Runtime signing for the app lives in backend/hardware_wallet.py + backend/verify.py.
Message format: "{sender_id}->{receiver_id}:{amount}:{signing_id}"
EdDSA via PyNaCl (same as generate_transactions.py).
"""
import hashlib

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def decrypt_private_key(encrypted_hex, pin):
    key = hashlib.sha256(pin.encode()).digest()
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = bytes(
        [b ^ key[i % len(key)] for i, b in enumerate(encrypted_bytes)]
    )
    return decrypted.hex()


def sign_transaction(private_key_hex, message):
    signing_key = SigningKey(bytes.fromhex(private_key_hex))
    return signing_key.sign(message.encode()).signature.hex()


def verify_signature(public_key_hex, message, signature_hex):
    verify_key = VerifyKey(bytes.fromhex(public_key_hex))
    try:
        verify_key.verify(message.encode(), bytes.fromhex(signature_hex))
        return True
    except BadSignatureError:
        return False
