-- ================================================================
-- HITECH BANK — SUPABASE SQL SETUP
-- Run this ENTIRE file in Supabase → SQL Editor → New Query → Run
--
-- If login returns: "Could not find the function public.check_user_password"
-- (PGRST202): these RPCs were never created — run at least the extension
-- line, all CREATE FUNCTION blocks below, and the GRANT section at the end.
-- ================================================================

-- Enable pgcrypto if not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ================================================================
-- TABLES (run only if starting fresh — skip if tables exist)
-- ================================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    bank_id INTEGER,
    name TEXT,
    password_hash TEXT,
    transaction_pin_hash TEXT,
    phone TEXT UNIQUE,
    balance NUMERIC DEFAULT 10000,
    card_number TEXT UNIQUE,
    public_key TEXT,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    bank_id INTEGER,
    sender_id INTEGER,
    receiver_id INTEGER,
    sender_bank_id INTEGER,
    receiver_bank_id INTEGER,
    amount NUMERIC,
    signature TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blocks (
    id SERIAL PRIMARY KEY,
    block_number INTEGER,
    prev_hash TEXT,
    current_hash TEXT,
    total_transactions INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

-- One row per block_number (avoids ambiguous "latest block" when inserting)
CREATE UNIQUE INDEX IF NOT EXISTS blocks_block_number_uidx ON blocks (block_number);

CREATE TABLE IF NOT EXISTS block_transactions (
    id SERIAL PRIMARY KEY,
    block_id INTEGER REFERENCES blocks(id),
    transaction_id INTEGER REFERENCES transactions(id),
    UNIQUE(block_id, transaction_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action TEXT,
    details TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fraud_flags (
    id SERIAL PRIMARY KEY,
    transaction_id INTEGER,
    reason TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ================================================================
-- RPC FUNCTION 1: check_user_password
-- Called by backend login to verify bcrypt password
-- ================================================================
CREATE OR REPLACE FUNCTION check_user_password(p_phone TEXT, p_password TEXT)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user users%ROWTYPE;
    v_valid BOOLEAN;
BEGIN
    SELECT * INTO v_user FROM users WHERE phone = p_phone;

    IF NOT FOUND THEN
        RETURN json_build_object('valid', false, 'user_id', null);
    END IF;

    v_valid := (v_user.password_hash = crypt(p_password, v_user.password_hash));

    IF v_valid THEN
        RETURN json_build_object('valid', true, 'user_id', v_user.id);
    ELSE
        RETURN json_build_object('valid', false, 'user_id', null);
    END IF;
END;
$$;

-- ================================================================
-- RPC FUNCTION 2: check_user_pin
-- Called by backend to verify transaction PIN
-- ================================================================
CREATE OR REPLACE FUNCTION check_user_pin(p_user_id INTEGER, p_pin TEXT)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user users%ROWTYPE;
    v_valid BOOLEAN;
BEGIN
    SELECT * INTO v_user FROM users WHERE id = p_user_id;

    IF NOT FOUND THEN
        RETURN json_build_object('valid', false);
    END IF;

    v_valid := (v_user.transaction_pin_hash = crypt(p_pin, v_user.transaction_pin_hash));

    RETURN json_build_object('valid', v_valid);
END;
$$;

-- ================================================================
-- RPC FUNCTION 3: create_user_with_hash
-- Called by backend signup to create user with hashed password+PIN
-- ================================================================
CREATE OR REPLACE FUNCTION create_user_with_hash(
    p_name TEXT,
    p_password TEXT,
    p_pin TEXT,
    p_phone TEXT,
    p_public_key TEXT,
    p_bank_id INTEGER,
    p_card_number TEXT
)
RETURNS JSON
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_user_id INTEGER;
BEGIN
    INSERT INTO users (name, password_hash, transaction_pin_hash, phone, public_key, bank_id, card_number, balance, is_admin)
    VALUES (
        p_name,
        crypt(p_password, gen_salt('bf')),
        crypt(p_pin, gen_salt('bf')),
        p_phone,
        p_public_key,
        p_bank_id,
        p_card_number,
        10000,
        FALSE
    )
    RETURNING id INTO v_user_id;

    RETURN json_build_object('user_id', v_user_id, 'success', true);
EXCEPTION
    WHEN unique_violation THEN
        RETURN json_build_object('user_id', null, 'success', false, 'error', 'Phone or card already exists');
END;
$$;

-- ================================================================
-- GRANTS — required so PostgREST can invoke RPCs (anon / service_role key)
-- ================================================================
GRANT EXECUTE ON FUNCTION public.check_user_password(text, text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.check_user_pin(integer, text) TO anon, authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.create_user_with_hash(text, text, text, text, text, integer, text) TO anon, authenticated, service_role;

-- ================================================================
-- EXISTING USERS — if you already have users inserted with
-- crypt() passwords, they will work fine with check_user_password.
-- ================================================================

