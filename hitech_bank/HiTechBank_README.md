# HiTech Bank — Blockchain-Secured Banking Demo

A full-stack banking application that implements **cryptographic transaction security** using real EdDSA (Ed25519) digital signatures, a custom SHA-256 blockchain ledger, Firebase OTP authentication, and JWT-based authorization.

> **What this is:** A security-focused banking demo. All accounts and transactions are test data.

This project demonstrates how cryptographic verification can prevent unauthorized or tampered financial transactions.

---

## What Makes This Different

Most student banking projects use basic username/password and store transactions in a table. This project layers in **real cryptographic security primitives** used in production fintech:

- Every transaction is **signed with the sender's Ed25519 private key** before it's accepted
- The backend **re-derives and verifies the signature** independently — you can't fake a transfer
- All committed transactions are **chained into a SHA-256 blockchain ledger** — tamper one record and the entire chain's hashes break
- Login uses **Firebase phone OTP** — no plaintext passwords in the auth flow

---

## Security Architecture

### Transfer Flow (Step by Step)

```
User fills transfer form
        │
        ▼
1. Backend validates transaction PIN via Supabase RPC
        │
        ▼
2. Backend verifies wallet PIN against stored SHA-256 hash
        │
        ▼
3. Private key is XOR-decrypted using SHA-256(wallet_pin) as key material
        │
        ▼
4. Canonical message built:  sender_id->receiver_id:amount:tx_index
        │
        ▼
5. Ed25519 signature generated using PyNaCl
        │
        ▼
6. Frontend sends transfer request WITH signature payload
        │
        ▼
7. Backend re-derives canonical message, verifies signature against stored public key
        │
        ▼
8. On verification success: balances updated, audit logged, blockchain appended
```

If signature verification fails at step 7, the transfer is rejected regardless of PIN correctness.

### Key Storage Model
- **Private keys** are XOR-encrypted with `SHA-256(wallet_pin)` before being written to `wallet_store/wallet.json`
- **Public keys** are stored in Supabase alongside user records
- **PIN hashes** (`SHA-256`) stored — never raw PINs
- No raw private keys are ever sent over the network

---

## Blockchain Ledger

A custom blockchain is implemented from scratch in `backend/blockchain.py`:

- **Block capacity:** 15 transactions per block
- **Block hash:** `SHA-256` over all transactions in the block, sorted by transaction ID (deterministic and verifiable)
- **Chain linkage:** Each block stores `prev_hash` of the previous block
- **Genesis block:** `prev_hash = "0"`
- **Integrity check:** `/api/blockchain/verify` re-hashes every block and validates the full prev-hash chain — any tampering (amount change, reorder, deletion) breaks the hashes

```
Block 1  ──prev_hash="0"──  hash=a3f1...
    │
Block 2  ──prev_hash=a3f1── hash=7c2d...
    │
Block 3  ──prev_hash=7c2d── hash=...
```

The blockchain is stored in Supabase (`blocks` + `block_transactions` tables), not in memory — it persists across restarts.

---

## Tech Stack

| Component | Tech |
|---|---|
| Backend | Python, Flask |
| Database | Supabase (PostgreSQL + RPCs) |
| Auth | Firebase Admin SDK (phone OTP) + PyJWT |
| Cryptography | PyNaCl (Ed25519), SHA-256 (hashlib), bcrypt |
| Frontend | HTML, Tailwind CSS, Vanilla JS |
| Key storage | JSON-based wallet store (encrypted at rest) |

---

## Project Structure

```
hitech_bank/
├── backend/
│   ├── app.py                  # Flask routes and API handlers
│   ├── auth.py                 # JWT helpers, auth decorators, card generation
│   ├── db.py                   # Supabase REST wrapper
│   ├── transaction.py          # Transfer processing, history, PIN checks
│   ├── verify.py               # Signature verification
│   ├── blockchain.py           # Block append + SHA-256 chain hashing
│   ├── hardware_wallet.py      # Wallet PIN check, key decrypt, EdDSA signing
│   └── audit.py                # Audit log and fraud flag access
├── frontend/
│   └── templates/
│       ├── login.html          # Firebase OTP login
│       ├── dashboard.html      # Balance + transfer UI
│       ├── account.html        # Account details
│       ├── blockchain.html     # Live blockchain viewer
│       ├── Transaction_history.html
│       └── project_visualization.html  # Architecture diagram
├── wallet_store/
│   └── wallet.json             # Encrypted private keys + PIN hashes
├── supabase_setup.sql
├── requirements.txt
└── Digital_Signature_Transaction.py   # Standalone signature test script
```

---

## Setup

### 1. Database
Run `supabase_setup.sql` in your Supabase SQL Editor. This creates the required tables and RPCs:
- `check_user_password`, `check_user_pin`, `create_user_with_hash`

### 2. Firebase
Create a Firebase project → enable Phone Authentication → download Admin SDK JSON.  
Place it at `backend/serviceAccountKey.json`.

### 3. Environment
Create `backend/.env`:
```env
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_KEY=your_supabase_anon_key
JWT_SECRET=your_long_random_secret
ADMIN_ACCESS_KEY=your_admin_key
FIREBASE_PROJECT_ID=your-firebase-project-id
```

### 4. Install dependencies
```bash
pip install -r requirements.txt
```

### 5. Run
```bash
cd backend
python app.py
```
Open: `http://localhost:5000`

---

## API Reference

### Auth
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/verify-firebase` | Verify Firebase OTP token |
| POST | `/api/auth/login` | Login with phone + password + Firebase token |
| POST | `/api/auth/signup` | Register user, generate Ed25519 keypair, issue JWT |
| POST | `/api/auth/verify-admin` | Re-issue token with admin role |

### Transactions
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/wallet/sign` | JWT | Validate PINs, decrypt key, return Ed25519 signature |
| POST | `/api/transaction/send` | JWT | Verify signature, commit transfer, update blockchain |
| GET | `/api/transaction/history` | JWT | User transaction history |

### Blockchain
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/blockchain/blocks` | JWT | List all blocks with transactions |
| GET | `/api/blockchain/verify` | JWT | Run full chain integrity check |

### Admin
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/admin/blockchain` | Admin JWT | Full blockchain data |
| GET | `/api/admin/audit-logs` | Admin JWT | Audit log stream |
| GET | `/api/admin/fraud-flags` | Admin JWT | Anomaly records |
| GET | `/api/admin/users` | Admin JWT | All user summaries |
| GET | `/api/admin/all-transactions` | Admin JWT | System-wide transaction ledger |

---

## Known Issues / Limitations

- `transfer.html` template is referenced in `backend/app.py` but not present — transfer is handled via `dashboard.html`. This route will 404 if hit directly.
- XOR encryption with a SHA-256 derived key is a simplified key-protection scheme — in production, use AES-GCM or a proper KMS.
- `wallet.json` is file-based; production would use HSM or secure enclave storage.
- Phone OTP via Firebase requires a real phone number; use Firebase test numbers for local dev.

---

## Concepts Demonstrated

`Ed25519 Digital Signatures` · `Blockchain Implementation` · `SHA-256 Hashing` · `Firebase OTP Auth` · `JWT Authorization` · `PostgreSQL RPCs` · `Cryptographic Key Management` · `Audit Logging` · `Flask` · `PyNaCl`
