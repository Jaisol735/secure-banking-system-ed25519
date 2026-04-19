from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from db import db_get
from hardware_wallet import canonical_amount_str


def build_transaction_sign_message(sender_id, receiver_id, amount, signing_id):
    """Exact string signed by the wallet (matches hardware_wallet.sign_with_wallet)."""
    return (
        f"{int(sender_id)}->{int(receiver_id)}:"
        f"{canonical_amount_str(amount)}:{int(signing_id)}"
    )


def verify_signature(public_key_hex, message, signature_hex):
    """Verify EdDSA (NaCl) signature over raw message bytes."""
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(message.encode(), bytes.fromhex(signature_hex))
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False


def get_public_key(sender_id):
    """Get public key from users table"""
    users = db_get("users", params={"id": f"eq.{sender_id}", "select": "public_key"})
    if users and len(users) > 0:
        return users[0].get("public_key")
    return None


def verify_transaction_signature_strict(sender_id, receiver_id, amount, signing_id, signature_hex):
    """
    Verify transfer signature using DB public key and server-rebuilt message only.
    """
    public_key_hex = get_public_key(sender_id)
    if not public_key_hex:
        return False, "Sender public key not found"

    message = build_transaction_sign_message(sender_id, receiver_id, amount, signing_id)
    if not verify_signature(public_key_hex, message, signature_hex):
        return False, "Invalid digital signature"

    return True, "Signature verified"


def verify_transaction_signature(sender_id, message, signature_hex):
    """Legacy: verify when message is already known (prefer verify_transaction_signature_strict)."""
    public_key_hex = get_public_key(sender_id)
    if not public_key_hex:
        return False, "Sender not found"

    if not verify_signature(public_key_hex, message, signature_hex):
        return False, "Invalid digital signature"

    return True, "Signature verified"
