import os
import sys
import hashlib

sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, render_template, send_from_directory, g
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

import firebase_admin
from firebase_admin import credentials, auth as firebase_auth

from db import db_get, db_post, db_patch, db_rpc
from verify import verify_transaction_signature_strict
from transaction import (
    process_transaction,
    get_user_transactions,
    verify_transaction_pin,
    get_user_by_card,
    peek_next_transaction_id,
)
from audit import log_action, get_audit_logs, get_fraud_flags
from blockchain import add_transaction_to_blockchain, get_blockchain, verify_blockchain_integrity
from hardware_wallet import sign_with_wallet, verify_wallet_pin, generate_and_store_keys
from auth import (
    generate_jwt,
    decode_jwt,
    require_auth,
    require_admin,
    ADMIN_ACCESS_KEY,
    generate_card_number,
)

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "../frontend/templates"),
    static_folder=os.path.join(os.path.dirname(__file__), "../frontend/static")
)
CORS(app)

# ========================
# FIREBASE INIT
# ========================
cred_path = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")
if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)


# ========================
# PAGE ROUTES
# ========================
@app.route("/")
def index():
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/account")
def account():
    return render_template("account.html")


@app.route("/transactions")
def transactions_page():
    return render_template("Transaction_history.html")


@app.route("/blockchain-view")
def blockchain_view():
    return render_template("blockchain.html")


@app.route("/visualization")
def visualization():
    return render_template("project_visualization.html")


@app.route("/transfer")
def transfer():
    return render_template("transfer.html")


# ========================
# AUTH APIS
# ========================
@app.route("/api/auth/verify-firebase", methods=["POST"])
def verify_firebase():
    """Step 1: Verify Firebase token before login/signup"""
    data = request.get_json()
    id_token = data.get("id_token")
    if not id_token:
        return jsonify({"error": "id_token required"}), 400
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        phone = decoded.get("phone_number", "")
        clean_phone = phone.replace("+91", "").replace(" ", "").strip()
        return jsonify({"success": True, "phone": clean_phone})
    except Exception as e:
        return jsonify({"error": f"Invalid token: {str(e)}"}), 401


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    phone = data.get("phone", "").replace("+91", "").replace(" ", "").strip()
    password = data.get("password")
    firebase_token = data.get("firebase_token")

    if not all([name, phone, password, firebase_token]):
        return jsonify({"error": "name, phone, password, firebase_token required"}), 400

    # Verify Firebase token
    try:
        decoded = firebase_auth.verify_id_token(firebase_token)
        fb_phone = decoded.get("phone_number", "").replace("+91", "").replace(" ", "").strip()
        if fb_phone != phone:
            return jsonify({"error": "Phone mismatch with OTP verification"}), 401
    except Exception as e:
        return jsonify({"error": f"Firebase verification failed: {str(e)}"}), 401

    # Verify password via Supabase RPC
    result = db_rpc("check_user_password", {"p_phone": phone, "p_password": password})
    if not result or not result.get("valid"):
        return jsonify({"error": "Invalid phone or password"}), 401

    user_id = result.get("user_id")
    users = db_get(
        "users",
        params={"id": f"eq.{user_id}", "select": "id,name,is_admin,bank_id,card_number,phone"},
    )
    if not users:
        return jsonify({"error": "User not found"}), 404

    user = users[0]
    if (user.get("name") or "").strip().casefold() != name.casefold():
        return jsonify({"error": "Name does not match this account"}), 401

    token = generate_jwt(user["id"], user["is_admin"])

    log_action(user["id"], "LOGIN", f"User {user['name']} logged in")

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "is_admin": user["is_admin"],
            "bank_id": user["bank_id"],
            "card_number": user["card_number"],
            "phone": user["phone"]
        }
    })


@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.get_json()
    name = data.get("name")
    phone = data.get("phone", "").replace("+91", "").replace(" ", "").strip()
    password = data.get("password")
    pin = data.get("pin")
    bank_id = data.get("bank_id", 1)
    firebase_token = data.get("firebase_token")
    wallet_pin = data.get("wallet_pin", "0726")

    if not all([name, phone, password, pin, firebase_token]):
        return jsonify({"error": "All fields required"}), 400

    # Verify Firebase token
    try:
        decoded = firebase_auth.verify_id_token(firebase_token)
        fb_phone = decoded.get("phone_number", "").replace("+91", "").replace(" ", "").strip()
        if fb_phone != phone:
            return jsonify({"error": "Phone mismatch with OTP verification"}), 401
    except Exception as e:
        return jsonify({"error": f"Firebase verification failed: {str(e)}"}), 401

    # Check if phone already exists
    existing = db_get("users", params={"phone": f"eq.{phone}", "select": "id"})
    if existing:
        return jsonify({"error": "Phone number already registered"}), 409

    # 16-digit card: entropy from serviceAccountKey.json + OS CSPRNG (auth.generate_card_number)
    card_number = None
    for _ in range(24):
        candidate = generate_card_number()
        clash = db_get("users", params={"card_number": f"eq.{candidate}", "select": "id"})
        if not clash:
            card_number = candidate
            break
    if not card_number:
        return jsonify({"error": "Could not allocate a unique card number"}), 500

    # Create user with hashed password/pin via RPC
    result = db_rpc("create_user_with_hash", {
        "p_name": name,
        "p_password": password,
        "p_pin": pin,
        "p_phone": phone,
        "p_public_key": "",  # placeholder until keys generated
        "p_bank_id": int(bank_id),
        "p_card_number": card_number
    })

    if not result:
        return jsonify({"error": "Failed to create user"}), 500

    user_id = result.get("user_id")

    # Wallet keys: same crypto as hardware_wallet/key_user_generation.py (Ed25519 + XOR encrypt in wallet_store/wallet.json)
    public_key = generate_and_store_keys(user_id, wallet_pin)

    # Update public key in DB
    db_patch("users", {"id": f"eq.{user_id}"}, {"public_key": public_key})

    token = generate_jwt(user_id, False)
    log_action(user_id, "SIGNUP", f"New user {name} registered")

    return jsonify({
        "success": True,
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "is_admin": False,
            "bank_id": int(bank_id),
            "card_number": card_number,
            "phone": phone
        }
    })


@app.route("/api/auth/verify-admin", methods=["POST"])
@require_auth
def verify_admin():
    """Re-issue JWT: full admin (7350) → admin123; anything else → user123 (downgrade)."""
    data = request.get_json()
    access_key = data.get("access_key")
    user_id = g.user["user_id"]

    if access_key == ADMIN_ACCESS_KEY:
        token = generate_jwt(user_id, True)
        return jsonify({"success": True, "token": token, "role": "admin123"})
    token = generate_jwt(user_id, False)
    return jsonify({"success": True, "token": token, "role": "user123"})


# ========================
# USER APIS
# ========================
@app.route("/api/user/profile", methods=["GET"])
@require_auth
def get_profile():
    user_id = g.user["user_id"]
    users = db_get("users", params={
        "id": f"eq.{user_id}",
        "select": "id,name,phone,card_number,bank_id,public_key,is_admin,created_at"
    })
    if not users:
        return jsonify({"error": "User not found"}), 404
    return jsonify(users[0])


@app.route("/api/user/balance", methods=["POST"])
@require_auth
def check_balance():
    """Check balance - requires transaction PIN"""
    data = request.get_json()
    pin = data.get("pin")
    user_id = g.user["user_id"]

    if not pin:
        return jsonify({"error": "Transaction PIN required"}), 400

    # Verify PIN via RPC
    result = db_rpc("check_user_pin", {"p_user_id": user_id, "p_pin": pin})
    if not result or not result.get("valid"):
        return jsonify({"error": "Invalid transaction PIN"}), 401

    users = db_get("users", params={"id": f"eq.{user_id}", "select": "balance,name"})
    if not users:
        return jsonify({"error": "User not found"}), 404

    log_action(user_id, "BALANCE_CHECK", f"User {user_id} checked balance")
    return jsonify({"balance": users[0]["balance"], "name": users[0]["name"]})


# ========================
# WALLET SIGNING API
# ========================
@app.route("/api/wallet/sign", methods=["POST"])
@require_auth
def wallet_sign():
    """Sign transaction with hardware wallet - returns signature to frontend"""
    data = request.get_json()
    wallet_pin = data.get("wallet_pin")
    receiver_card = data.get("receiver_card")
    amount = data.get("amount")
    transaction_pin = data.get("transaction_pin")

    user_id = g.user["user_id"]

    if not all([wallet_pin, receiver_card, amount, transaction_pin]):
        return jsonify({"error": "All fields required"}), 400

    # Verify transaction PIN
    result = db_rpc("check_user_pin", {"p_user_id": user_id, "p_pin": transaction_pin})
    if not result or not result.get("valid"):
        return jsonify({"error": "Invalid transaction PIN"}), 401

    # Get receiver
    receiver = get_user_by_card(receiver_card)
    if not receiver:
        return jsonify({"error": "Receiver card not found"}), 404

    if receiver["id"] == user_id:
        return jsonify({"error": "Cannot send to yourself"}), 400

    # Get sender info
    senders = db_get("users", params={"id": f"eq.{user_id}", "select": "id,name,bank_id,balance"})
    if not senders:
        return jsonify({"error": "Sender not found"}), 404
    sender = senders[0]

    if float(sender["balance"]) < float(amount):
        return jsonify({"error": "Insufficient balance"}), 400

    signing_id = peek_next_transaction_id()

    # Sign with wallet (message includes predicted DB transaction id, like generate_transactions.py index i)
    sign_result, err = sign_with_wallet(
        user_id=user_id,
        pin=wallet_pin,
        sender_id=user_id,
        receiver_id=receiver["id"],
        amount=amount,
        tx_index=signing_id,
    )

    if err:
        return jsonify({"error": err}), 401
    if sign_result is None:
        return jsonify({"error": "Signing failed"}), 500

    return jsonify({
        "success": True,
        "signature": sign_result["signature"],
        "message": sign_result["message"],
        "signing_id": signing_id,
        "receiver_id": receiver["id"],
        "receiver_name": receiver["name"],
        "receiver_bank_id": receiver["bank_id"],
        "sender_bank_id": sender["bank_id"],
        "amount": float(amount)
    })


# ========================
# TRANSACTION API
# ========================
@app.route("/api/transaction/send", methods=["POST"])
@require_auth
def send_money():
    """Execute transaction after wallet signing"""
    data = request.get_json()
    receiver_id = data.get("receiver_id")
    amount = data.get("amount")
    signature = data.get("signature")
    signing_id = data.get("signing_id")
    sender_bank_id = data.get("sender_bank_id")
    receiver_bank_id = data.get("receiver_bank_id")

    user_id = g.user["user_id"]

    if not all([receiver_id, amount, signature]) or signing_id is None:
        return jsonify({"error": "receiver_id, amount, signature, signing_id required"}), 400

    try:
        signing_id = int(signing_id)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid signing_id"}), 400

    if int(receiver_id) == user_id:
        return jsonify({"error": "Cannot send to yourself"}), 400

    if float(amount) <= 0:
        return jsonify({"error": "Amount must be positive"}), 400

    expected_slot = peek_next_transaction_id()
    if signing_id != expected_slot:
        log_action(user_id, "FAILED_TRANSFER", "Signature slot mismatch (sign again)")
        return jsonify({
            "error": "Signature is stale or invalid — open Send Money and sign again",
        }), 401

    # Rebuild signed message server-side (never trust client-supplied message)
    valid, msg = verify_transaction_signature_strict(
        user_id, int(receiver_id), float(amount), signing_id, signature
    )
    if not valid:
        log_action(user_id, "FAILED_TRANSFER", f"Signature verification failed: {msg}")
        return jsonify({"error": f"Signature verification failed: {msg}"}), 401

    # Determine bank_id (use sender's)
    senders = db_get("users", params={"id": f"eq.{user_id}", "select": "bank_id"})
    bank_id = senders[0]["bank_id"] if senders else sender_bank_id

    # Step 2: Process transaction
    tx, err = process_transaction(
        bank_id=bank_id,
        sender_id=user_id,
        receiver_id=int(receiver_id),
        sender_bank_id=sender_bank_id or bank_id,
        receiver_bank_id=receiver_bank_id or bank_id,
        amount=float(amount),
        signature=signature
    )

    if err:
        return jsonify({"error": err}), 400

    tx_id = tx["id"] if isinstance(tx, dict) else tx

    # Step 3: Audit log
    log_action(user_id, "TRANSFER", f"User {user_id} sent {amount} to User {receiver_id}")

    # Step 4: Blockchain
    tx_full = {
        "sender_id": user_id,
        "sender_bank_id": sender_bank_id or bank_id,
        "receiver_id": int(receiver_id),
        "receiver_bank_id": receiver_bank_id or bank_id,
        "amount": float(amount),
        "signature": signature
    }
    bc = add_transaction_to_blockchain(tx_id, tx_full)

    if not bc.get("ok"):
        log_action(
            user_id,
            "BLOCKCHAIN_ERROR",
            f"tx {tx_id}: {bc.get('error')} (transfer already committed)",
        )

    return jsonify({
        "success": True,
        "message": "Transaction completed",
        "transaction_id": tx_id,
        "audit": "logged",
        "blockchain": {
            "status": "complete" if bc.get("ok") else "error",
            "block_number": bc.get("block_number"),
            "current_hash": bc.get("current_hash"),
            "total_transactions": bc.get("total_transactions"),
            "detail": bc.get("message") if bc.get("ok") else bc.get("error"),
        },
    })


@app.route("/api/transaction/history", methods=["GET"])
@require_auth
def transaction_history():
    user_id = g.user["user_id"]
    txs = get_user_transactions(user_id)

    # Enrich with user names
    user_cache = {}
    def get_name(uid):
        if uid not in user_cache:
            u = db_get("users", params={"id": f"eq.{uid}", "select": "name"})
            user_cache[uid] = u[0]["name"] if u else f"User {uid}"
        return user_cache[uid]

    for tx in txs:
        tx["sender_name"] = get_name(tx["sender_id"])
        tx["receiver_name"] = get_name(tx["receiver_id"])

    return jsonify(txs)


# ========================
# ADMIN APIS
# ========================
@app.route("/api/admin/blockchain", methods=["GET"])
@require_admin
def admin_blockchain():
    blocks = get_blockchain()
    integrity = verify_blockchain_integrity()
    return jsonify({"blocks": blocks, "integrity": integrity})


@app.route("/api/admin/audit-logs", methods=["GET"])
@require_admin
def admin_audit_logs():
    logs = get_audit_logs()
    return jsonify(logs)


@app.route("/api/admin/fraud-flags", methods=["GET"])
@require_admin
def admin_fraud():
    flags = get_fraud_flags()
    return jsonify(flags)


@app.route("/api/admin/users", methods=["GET"])
@require_admin
def admin_users():
    users = db_get("users", params={
        "select": "id,name,phone,bank_id,balance,card_number,is_admin,created_at",
        "order": "id.asc"
    })
    return jsonify(users or [])


@app.route("/api/admin/all-transactions", methods=["GET"])
@require_admin
def admin_transactions():
    txs = db_get("transactions", params={
        "select": "id,bank_id,sender_id,receiver_id,amount,status,created_at,sender_bank_id,receiver_bank_id",
        "order": "created_at.desc"
    })
    return jsonify(txs or [])


# ========================
# BLOCKCHAIN VERIFY API
# ========================
@app.route("/api/blockchain/verify", methods=["GET"])
@require_auth
def verify_chain():
    result = verify_blockchain_integrity()
    return jsonify(result)


@app.route("/api/blockchain/blocks", methods=["GET"])
@require_auth
def get_blocks():
    blocks = get_blockchain()
    return jsonify(blocks)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
