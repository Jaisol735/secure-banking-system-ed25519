from db import db_get, db_post, db_patch, db_rpc


def peek_next_transaction_id():
    """Next transactions.id if we INSERT now (used as signing slot / message index)."""
    rows = db_get(
        "transactions",
        params={"select": "id", "order": "id.desc", "limit": "1"},
    )
    if not rows:
        return 1
    return int(rows[0]["id"]) + 1


def process_transaction(bank_id, sender_id, receiver_id, sender_bank_id, receiver_bank_id, amount, signature):
    """Insert transaction and update balances"""
    # Validate sender exists and has balance
    senders = db_get("users", params={"id": f"eq.{sender_id}", "select": "id,balance,name"})
    if not senders:
        return None, "Sender not found"
    sender = senders[0]

    if float(sender["balance"]) < float(amount):
        return None, "Insufficient balance"

    # Validate receiver exists
    receivers = db_get("users", params={"id": f"eq.{receiver_id}", "select": "id,balance,name"})
    if not receivers:
        return None, "Receiver not found"
    receiver = receivers[0]

    # Insert transaction
    tx_data = {
        "bank_id": bank_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "sender_bank_id": sender_bank_id,
        "receiver_bank_id": receiver_bank_id,
        "amount": float(amount),
        "signature": signature,
        "status": "confirmed"
    }

    tx_result = db_post("transactions", tx_data)
    if not tx_result:
        return None, "Failed to insert transaction"

    tx = tx_result[0] if isinstance(tx_result, list) else tx_result

    # Update sender balance (deduct)
    new_sender_balance = float(sender["balance"]) - float(amount)
    db_patch("users", {"id": f"eq.{sender_id}"}, {"balance": new_sender_balance})

    # Update receiver balance (add)
    new_receiver_balance = float(receiver["balance"]) + float(amount)
    db_patch("users", {"id": f"eq.{receiver_id}"}, {"balance": new_receiver_balance})

    return tx, None


def get_user_transactions(user_id):
    """Get all transactions for a user"""
    # Sent transactions
    sent = db_get("transactions", params={
        "sender_id": f"eq.{user_id}",
        "select": "id,bank_id,sender_id,receiver_id,amount,signature,status,created_at,sender_bank_id,receiver_bank_id",
        "order": "created_at.desc"
    }) or []

    # Received transactions
    received = db_get("transactions", params={
        "receiver_id": f"eq.{user_id}",
        "select": "id,bank_id,sender_id,receiver_id,amount,signature,status,created_at,sender_bank_id,receiver_bank_id",
        "order": "created_at.desc"
    }) or []

    # Mark direction
    for t in sent:
        t["direction"] = "sent"
    for t in received:
        t["direction"] = "received"

    # Combine and sort
    all_tx = sent + received
    all_tx.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return all_tx


def verify_transaction_pin(user_id, pin):
    """Verify transaction PIN using Supabase RPC"""
    result = db_rpc("check_user_pin", {"p_user_id": user_id, "p_pin": pin})
    if result and result.get("valid"):
        return True
    return False


def get_user_by_card(card_number):
    """Get user by card number"""
    users = db_get("users", params={
        "card_number": f"eq.{card_number}",
        "select": "id,name,bank_id,card_number"
    })
    if users:
        return users[0]
    return None
