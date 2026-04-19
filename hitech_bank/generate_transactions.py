"""
Batch demo: sign many transfers and POST to Supabase (optional dev script).

Set SUPABASE_URL and SUPABASE_KEY in environment or backend/.env — do not hardcode secrets.
Wallet file: wallet_store/wallet.json (project root), same layout as key_user_generation.
"""
import json
import hashlib
import os
import random
import sys

import requests
from dotenv import load_dotenv
from nacl.signing import SigningKey

_ROOT = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(_ROOT, "backend", ".env"))
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Set SUPABASE_URL and SUPABASE_KEY in backend/.env", file=sys.stderr)
    sys.exit(1)

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
}

WALLET_PATH = os.path.join(_ROOT, "wallet_store", "wallet.json")
with open(WALLET_PATH, "r", encoding="utf-8") as f:
    users = json.load(f)


def decrypt_private_key(encrypted_hex, pin):
    key = hashlib.sha256(pin.encode()).digest()
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted = bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_bytes)])
    return decrypted.hex()


def sign_transaction(private_key_hex, message):
    signing_key = SigningKey(bytes.fromhex(private_key_hex))
    return signing_key.sign(message.encode()).signature.hex()


transactions = []
audit_logs = []

for i in range(45):
    if i < 22:
        bank_id = 1
        sender = random.choice([1, 2])
        receiver = 2 if sender == 1 else 1
    else:
        bank_id = 2
        sender = random.choice([3, 4, 5])
        receiver = random.choice([x for x in [3, 4, 5] if x != sender])

    amount = random.randint(100, 5000)
    user = next(u for u in users if u["user_id"] == sender)

    private_key_hex = decrypt_private_key(user["encrypted_private_key"], "0726")
    message = f"{sender}->{receiver}:{amount}:{i}"
    signature = sign_transaction(private_key_hex, message)

    transactions.append(
        {
            "bank_id": bank_id,
            "sender_id": sender,
            "receiver_id": receiver,
            "amount": amount,
            "signature": signature,
            "status": "confirmed",
        }
    )

    audit_logs.append(
        {
            "user_id": sender,
            "action": "TRANSFER",
            "details": f"{sender} sent {amount} to {receiver}",
        }
    )

res = requests.post(
    f"{SUPABASE_URL}/rest/v1/transactions",
    headers=HEADERS,
    json=transactions,
)
print("Transactions inserted:", res.status_code)

requests.post(
    f"{SUPABASE_URL}/rest/v1/audit_logs",
    headers=HEADERS,
    json=audit_logs,
)
print("Audit logs inserted")
