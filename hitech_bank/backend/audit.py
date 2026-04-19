from db import db_post, db_get


def log_action(user_id, action, details):
    """Insert audit log entry"""
    data = {
        "user_id": user_id,
        "action": action,
        "details": details
    }
    result = db_post("audit_logs", data)
    return result is not None


def get_audit_logs(user_id=None, limit=100):
    """Get audit logs, optionally filtered by user"""
    params = {
        "select": "id,user_id,action,details,created_at",
        "order": "created_at.desc",
        "limit": str(limit)
    }
    if user_id:
        params["user_id"] = f"eq.{user_id}"

    return db_get("audit_logs", params=params) or []


def get_fraud_flags():
    """Get all fraud flags"""
    return db_get("fraud_flags", params={
        "select": "id,transaction_id,reason,created_at",
        "order": "created_at.desc"
    }) or []


def flag_fraud(transaction_id, reason):
    """Flag a transaction as fraudulent"""
    data = {
        "transaction_id": transaction_id,
        "reason": reason
    }
    return db_post("fraud_flags", data)
