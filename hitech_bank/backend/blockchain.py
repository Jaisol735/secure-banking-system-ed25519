"""
Blockchain: blocks of up to 15 transactions, SHA-256 over canonical tx lines.

Equivalent to Postgres STRING_AGG of:
  sender_id || '-' || sender_bank_id || '-' ||
  receiver_id || '-' || receiver_bank_id || '-' ||
  amount || '-' || signature
joined by '|', with transactions ordered by transaction id (stable, verifiable).

Uses block_id + block_transactions (FK) — same logical model as filtering by block_number.
"""

import hashlib
from db import db_get, db_post, db_patch
from hardware_wallet import canonical_amount_str

BLOCK_CAPACITY = 15
GENESIS_PREV_HASH = "0"


def _tx_line(tx):
    """One transaction segment: sender_id-sender_bank_id-receiver_id-receiver_bank_id-amount-signature"""
    return (
        f"{tx['sender_id']}-{tx['sender_bank_id']}-"
        f"{tx['receiver_id']}-{tx['receiver_bank_id']}-"
        f"{canonical_amount_str(tx['amount'])}-{tx['signature']}"
    )


def compute_block_hash(tx_rows):
    """
    SHA-256 hex over all txs in the block, sorted by transaction id ascending
    (deterministic; any order change would change the hash).
    """
    rows = [dict(t) for t in tx_rows]
    rows.sort(key=lambda t: int(t["id"]))
    tx_data = "|".join(_tx_line(t) for t in rows)
    return hashlib.sha256(tx_data.encode("utf-8")).hexdigest()


def get_full_transactions_for_block(block_id):
    """All transactions in this block, ordered by transaction_id (canonical chain order)."""
    bt_list = db_get(
        "block_transactions",
        params={
            "block_id": f"eq.{block_id}",
            "select": "transaction_id",
            "order": "transaction_id.asc",
        },
    ) or []

    ordered = []
    for bt in bt_list:
        tid = bt["transaction_id"]
        txs = db_get(
            "transactions",
            params={
                "id": f"eq.{tid}",
                "select": "id,sender_id,sender_bank_id,receiver_id,receiver_bank_id,amount,signature",
            },
        )
        if txs:
            ordered.append(txs[0])
    return ordered


def add_transaction_to_blockchain(transaction_id, tx):
    """
    Append transaction_id to the current block or open a new one when the latest has 15 txs.
    Re-hashes the open block from the full ordered tx set (same as re-STRING_AGG).

    Returns:
        dict with ok, error (if not ok), block_number, current_hash, total_transactions, message
    """
    blocks = db_get(
        "blocks",
        params={
            "select": "id,block_number,prev_hash,current_hash,total_transactions",
            "order": "block_number.desc",
            "limit": "1",
        },
    )

    if not blocks:
        return _create_new_block(1, GENESIS_PREV_HASH, transaction_id, tx)

    latest = blocks[0]
    total = int(latest.get("total_transactions") or 0)

    if total < BLOCK_CAPACITY:
        return _add_to_existing_block(latest, transaction_id, tx)

    prev_hash = latest.get("current_hash")
    if not prev_hash:
        return {
            "ok": False,
            "error": "Latest block has no current_hash; chain data may be corrupt",
            "block_number": None,
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    next_num = int(latest["block_number"]) + 1
    return _create_new_block(next_num, prev_hash, transaction_id, tx)


def _add_to_existing_block(block, new_tx_id, new_tx):
    block_id = block["id"]
    ins = db_post(
        "block_transactions",
        {"block_id": block_id, "transaction_id": new_tx_id},
    )
    if not ins:
        return {
            "ok": False,
            "error": "Failed to map transaction to block (duplicate or DB error)",
            "block_number": None,
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    all_tx = get_full_transactions_for_block(block_id)
    ids_present = {int(t["id"]) for t in all_tx}
    if int(new_tx_id) not in ids_present:
        all_tx.append(
            {
                "id": new_tx_id,
                "sender_id": new_tx["sender_id"],
                "sender_bank_id": new_tx["sender_bank_id"],
                "receiver_id": new_tx["receiver_id"],
                "receiver_bank_id": new_tx["receiver_bank_id"],
                "amount": new_tx["amount"],
                "signature": new_tx["signature"],
            }
        )

    new_hash = compute_block_hash(all_tx)
    new_total = len(all_tx)

    if not db_patch(
        "blocks",
        {"id": f"eq.{block_id}"},
        {"current_hash": new_hash, "total_transactions": new_total},
    ):
        return {
            "ok": False,
            "error": "Failed to update block hash after adding transaction",
            "block_number": block.get("block_number"),
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    return {
        "ok": True,
        "error": None,
        "block_number": block["block_number"],
        "current_hash": new_hash,
        "total_transactions": new_total,
        "message": "Blockchain complete — block updated and re-hashed",
    }


def _create_new_block(block_number, prev_hash, tx_id, tx):
    new_block = db_post(
        "blocks",
        {
            "block_number": block_number,
            "prev_hash": prev_hash,
            "current_hash": None,
            "total_transactions": 0,
        },
    )
    if not new_block:
        return {
            "ok": False,
            "error": "Failed to create block row",
            "block_number": None,
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    row = new_block[0] if isinstance(new_block, list) else new_block
    block_id = row["id"]

    ins = db_post(
        "block_transactions",
        {"block_id": block_id, "transaction_id": tx_id},
    )
    if not ins:
        return {
            "ok": False,
            "error": "Block created but failed to attach transaction",
            "block_number": block_number,
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    tx_list = [
        {
            "id": tx_id,
            "sender_id": tx["sender_id"],
            "sender_bank_id": tx["sender_bank_id"],
            "receiver_id": tx["receiver_id"],
            "receiver_bank_id": tx["receiver_bank_id"],
            "amount": tx["amount"],
            "signature": tx["signature"],
        }
    ]
    new_hash = compute_block_hash(tx_list)

    if not db_patch(
        "blocks",
        {"id": f"eq.{block_id}"},
        {"current_hash": new_hash, "total_transactions": 1},
    ):
        return {
            "ok": False,
            "error": "Failed to seal new block hash",
            "block_number": block_number,
            "current_hash": None,
            "total_transactions": None,
            "message": None,
        }

    return {
        "ok": True,
        "error": None,
        "block_number": block_number,
        "current_hash": new_hash,
        "total_transactions": 1,
        "message": "Blockchain complete — new block created and sealed",
    }


def get_blockchain():
    """All blocks with ordered transactions."""
    blocks = (
        db_get(
            "blocks",
            params={
                "select": "id,block_number,prev_hash,current_hash,total_transactions,created_at",
                "order": "block_number.asc",
            },
        )
        or []
    )

    result = []
    for block in blocks:
        txs = get_full_transactions_for_block(block["id"])
        result.append({**block, "transactions": txs})
    return result


def verify_blockchain_integrity():
    """Validate prev_hash chain and that current_hash matches recomputed SHA-256."""
    blocks = (
        db_get(
            "blocks",
            params={
                "select": "id,block_number,prev_hash,current_hash,total_transactions",
                "order": "block_number.asc",
            },
        )
        or []
    )

    issues = []
    expected_prev = GENESIS_PREV_HASH

    for block in blocks:
        bnum = block["block_number"]
        prev = block.get("prev_hash") or ""
        if prev != expected_prev:
            issues.append(
                f"Block {bnum}: prev_hash mismatch (expected {expected_prev!r}, got {prev!r})"
            )

        txs = get_full_transactions_for_block(block["id"])
        n = len(txs)
        stored_total = int(block.get("total_transactions") or 0)
        if n != stored_total:
            issues.append(
                f"Block {bnum}: total_transactions={stored_total} but {n} mapped rows"
            )

        if n > 0:
            if not block.get("current_hash"):
                issues.append(f"Block {bnum}: missing current_hash but has transactions")
            else:
                expected_hash = compute_block_hash(txs)
                if expected_hash != block["current_hash"]:
                    issues.append(
                        f"Block {bnum}: hash mismatch (tampered or ordering/amount changed)"
                    )
        else:
            if block.get("current_hash"):
                issues.append(f"Block {bnum}: empty but current_hash is set")

        # Next block's prev_hash must equal this block's stored seal (chain link)
        ch = block.get("current_hash")
        if ch:
            expected_prev = ch

    return {"valid": len(issues) == 0, "issues": issues}
