import os
import requests
from dotenv import load_dotenv

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

HEADERS = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}


def db_get(table, params=None, single=False):
    """GET from Supabase REST API"""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    headers = dict(HEADERS)
    if single:
        headers["Accept"] = "application/vnd.pgrst.object+json"
    r = requests.get(url, headers=headers, params=params)
    if r.status_code in (200, 201, 206):
        return r.json()
    return None


def db_post(table, data):
    """INSERT into Supabase"""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.post(url, headers=HEADERS, json=data)
    if r.status_code in (200, 201):
        return r.json()
    print(f"DB POST error {r.status_code}: {r.text}")
    return None


def db_patch(table, params, data):
    """UPDATE in Supabase"""
    url = f"{SUPABASE_URL}/rest/v1/{table}"
    r = requests.patch(url, headers=HEADERS, params=params, json=data)
    if r.status_code in (200, 204):
        return True
    print(f"DB PATCH error {r.status_code}: {r.text}")
    return False


def db_rpc(func_name, data):
    """Call Supabase RPC function"""
    url = f"{SUPABASE_URL}/rest/v1/rpc/{func_name}"
    r = requests.post(url, headers=HEADERS, json=data)
    if r.status_code in (200, 201):
        return r.json()
    print(f"DB RPC error {r.status_code}: {r.text}")
    return None
