import os
import json
import secrets
import hashlib
import jwt
import datetime
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from functools import wraps
from flask import request, jsonify, g
from dotenv import load_dotenv
from db import db_get, db_post, db_rpc

load_dotenv()

# HS256: PyJWT warns if secret is shorter than 32 bytes (RFC 7518). Hash short env values.
_jwt_env = os.getenv("JWT_SECRET", "hitech_bank_dev_change_me").strip()
JWT_SECRET = (
    _jwt_env
    if len(_jwt_env.encode("utf-8")) >= 32
    else hashlib.sha256(_jwt_env.encode("utf-8")).hexdigest()
)
ADMIN_ACCESS_KEY = os.getenv("ADMIN_ACCESS_KEY", "7350")

# Initialize Firebase Admin
cred_path = os.path.join(os.path.dirname(__file__), "serviceAccountKey.json")
if not firebase_admin._apps:
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)


def generate_card_number():
    """
    16-digit card number (4111 + 12 digits). Mixes entropy from
    serviceAccountKey.json (project_id, private_key_id) with OS CSPRNG so
    cards are unique and not predictable from the service file alone.
    """
    with open(cred_path, "r", encoding="utf-8") as f:
        sa = json.load(f)
    salt = (
        (sa.get("project_id") or "")
        + (sa.get("private_key_id") or "")
    ).encode("utf-8")
    digest = hashlib.sha256(salt + secrets.token_bytes(32)).digest()
    twelve = "".join(str(b % 10) for b in digest[:12])
    card = "4111" + twelve
    return card


def verify_firebase_token(id_token):
    """Verify Firebase ID token and return phone number"""
    try:
        decoded = firebase_auth.verify_id_token(id_token)
        return decoded.get("phone_number")
    except Exception as e:
        print(f"Firebase token error: {e}")
        return None


def generate_jwt(user_id, is_admin):
    """Generate JWT token. role claim: user123 | admin123 (per project spec)."""
    payload = {
        "user_id": user_id,
        "is_admin": is_admin,
        "role": "admin123" if is_admin else "user123",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=8),
        "iat": datetime.datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt(token):
    """Decode and validate JWT"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_auth(f):
    """Decorator to require valid JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Token expired or invalid"}), 401
        g.user = payload
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator to require admin JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header.split(" ")[1]
        payload = decode_jwt(token)
        if not payload:
            return jsonify({"error": "Token expired or invalid"}), 401
        if not payload.get("is_admin"):
            return jsonify({"error": "Admin access required"}), 403
        g.user = payload
        return f(*args, **kwargs)
    return decorated


def login_user(phone, password, firebase_token):
    """Login: verify firebase token + password"""
    # Step 1: Verify Firebase token
    firebase_phone = verify_firebase_token(firebase_token)
    if not firebase_phone:
        return None, "Invalid Firebase token"

    # Normalize phone numbers for comparison
    clean_phone = phone.replace("+91", "").replace(" ", "").strip()
    clean_firebase = firebase_phone.replace("+91", "").replace(" ", "").strip()

    if clean_phone != clean_firebase:
        return None, "Phone number mismatch with OTP"

    # Step 2: Get user from DB
    users = db_get("users", params={"phone": f"eq.{clean_phone}", "select": "*"})
    if not users:
        return None, "User not found"

    user = users[0]

    # Step 3: Verify password using Supabase RPC (bcrypt check)
    result = db_get("users", params={
        "phone": f"eq.{clean_phone}",
        "select": "id,name,is_admin,bank_id,card_number,public_key",
        "password_hash": f"eq.{password}"  # raw check won't work; use RPC
    })

    # Use RPC for bcrypt password check
    check = db_rpc("check_user_password", {"p_phone": clean_phone, "p_password": password})
    if not check or not check.get("valid"):
        return None, "Invalid password"

    return user, None


def signup_user(name, password, pin, phone, public_key, bank_id):
    """Signup new user"""
    card_number = generate_card_number()

    # Password and PIN will be hashed via RPC
    result = db_rpc("create_user_with_hash", {
        "p_name": name,
        "p_password": password,
        "p_pin": pin,
        "p_phone": phone,
        "p_public_key": public_key,
        "p_bank_id": bank_id,
        "p_card_number": card_number
    })

    return result
