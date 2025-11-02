"""
app.py
SecureVault — Alternate Secure FinTech App for CY4053 Assignment 2
Rebuilt with a light UI and a top navigation bar layout.
Author: For Academic Submission (Independent Version)
"""

import streamlit as st
import sqlite3
import os
import bcrypt
import re
import pandas as pd
import random
import string
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet

# -------------------------------
# Config
# -------------------------------
DB_FILE = "securevault_data.db"
KEY_FILE = "securevault_secret.key"
ALLOWED_FILES = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# -------------------------------
# Light Theme CSS
# -------------------------------
def set_light_theme():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #f7fafc 0%, #e9f3ff 100%);
            font-family: 'Poppins', sans-serif;
            color: #223;
        }
        .app-header {
            text-align: center;
            padding: 10px 0;
            background: #dceeff;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 20px;
        }
        .nav-bar {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 25px;
        }
        .nav-button {
            background-color: #ffffff;
            border: 1px solid #aad4ff;
            padding: 8px 18px;
            border-radius: 20px;
            cursor: pointer;
            color: #004d8c;
            font-weight: 600;
        }
        .nav-button:hover {
            background-color: #0078ff;
            color: white;
        }
        .main-card {
            background-color: white;
            border-radius: 14px;
            padding: 20px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.05);
        }
        h1, h2, h3 {
            color: #003366;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

# -------------------------------
# Crypto
# -------------------------------
def ensure_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

fernet = None
def init_crypto():
    global fernet
    key = ensure_key()
    fernet = Fernet(key)

def encrypt_data(text):
    return fernet.encrypt(text.encode())

def decrypt_data(blob):
    return fernet.decrypt(blob).decode()

# -------------------------------
# DB
# -------------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        tx_ref TEXT NOT NULL,
        tx_number TEXT NOT NULL,
        tx_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(wallet_id) REFERENCES wallets(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        detail TEXT,
        time TEXT
    )
    """)
    conn.commit()
    conn.close()

# -------------------------------
# Helper Functions
# -------------------------------
def hash_pw(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def verify_pw(p, h):
    try:
        return bcrypt.checkpw(p.encode(), h)
    except:
        return False

def sanitize(s):
    s = s.strip()
    if len(s) > 1000:
        s = s[:1000]
    if any(x in s.lower() for x in ["--", "drop", "delete", "insert", " or ", "=", " and "]):
        raise ValueError("Unsafe input detected.")
    return s

def log_action(uid, action, detail=None):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO logs(user_id, action, detail, time) VALUES (?,?,?,?)",
                  (uid, action, detail, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except:
        pass

# -------------------------------
# User Ops
# -------------------------------
def register_user(username, email, password):
    try:
        username = sanitize(username)
        email = sanitize(email)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    try:
        pw_hash = hash_pw(password)
        c.execute("INSERT INTO users(username, email, password_hash, created_at) VALUES(?,?,?,?)",
                  (username, email, pw_hash, datetime.utcnow().isoformat()))
        conn.commit()
        log_action(None, "register", username)
        return True, "Registration successful!"
    except sqlite3.IntegrityError:
        return False, "Username or email already exists."
    finally:
        conn.close()

def get_user(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    r = c.fetchone()
    conn.close()
    return r

def get_user_by_id(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = c.fetchone()
    conn.close()
    return r

# -------------------------------
# Wallet & Transaction
# -------------------------------
def create_wallet(uid, name, data):
    try:
        name = sanitize(name)
        data = sanitize(data)
        enc = encrypt_data(data)
    except ValueError as e:
        return False, str(e)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO wallets(owner_id, name, data, created_at) VALUES (?,?,?,?)",
              (uid, name, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    log_action(uid, "wallet_created", name)
    return True, "Wallet added."

def get_wallets(uid):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM wallets WHERE owner_id=?", (uid,))
    rows = c.fetchall()
    conn.close()
    return rows

def create_transaction(wallet_id, tx_number):
    if not tx_number.isdigit():
        return False, "Transaction number must be numeric."
    tx_ref = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    payload = f"{tx_ref}:{tx_number}"
    enc = encrypt_data(payload)
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO transactions(wallet_id, tx_ref, tx_number, tx_data, created_at) VALUES (?,?,?,?,?)",
              (wallet_id, tx_ref, tx_number, enc, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
    return True, f"Transaction {tx_ref} added."

def get_transactions(wallet_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT tx_ref, tx_number, created_at FROM transactions WHERE wallet_id=?", (wallet_id,))
    rows = c.fetchall()
    conn.close()
    return rows

# -------------------------------
# File Upload
# -------------------------------
def validate_file(uploaded):
    ext = uploaded.name.split(".")[-1].lower()
    if ext not in ALLOWED_FILES:
        return False, f".{ext} not allowed."
    if uploaded.size > 5 * 1024 * 1024:
        return False, "File exceeds 5MB."
    return True, "File accepted."

# -------------------------------
# Pages
# -------------------------------
def page_home():
    st.markdown("<div class='main-card'><h2>Welcome to SecureVault 💼</h2>"
                "<p>This app demonstrates secure FinTech operations with encryption and secure coding practices.</p></div>",
                unsafe_allow_html=True)

def page_register():
    st.subheader("Create an Account")
    with st.form("reg_form"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        pw = st.text_input("Password", type="password")
        c_pw = st.text_input("Confirm Password", type="password")
        s = st.form_submit_button("Register")
    if s:
        if pw != c_pw:
            st.warning("Passwords do not match.")
        else:
            ok, msg = register_user(username, email, pw)
            st.success(msg) if ok else st.error(msg)

def page_login():
    st.subheader("Login Securely")
    with st.form("login_form"):
        user = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
    if submit:
        u = get_user(user)
        if u and verify_pw(pw, u["password_hash"]):
            st.session_state["user_id"] = u["id"]
            st.session_state["username"] = u["username"]
            st.success(f"Welcome back, {u['username']}!")
            log_action(u["id"], "login")
        else:
            st.error("Invalid credentials or unsafe input detected.")

def page_wallets():
    if not logged_in(): return
    st.subheader("My Wallets")
    with st.form("add_wallet"):
        wname = st.text_input("Wallet Name")
        wdata = st.text_area("Wallet Secret Data")
        if st.form_submit_button("Create Wallet"):
            ok, msg = create_wallet(st.session_state["user_id"], wname, wdata)
            st.success(msg) if ok else st.error(msg)
    st.divider()
    wallets = get_wallets(st.session_state["user_id"])
    for w in wallets:
        st.markdown(f"**{w['name']}** — created {w['created_at']}")
        if st.button(f"View Encrypted Data #{w['id']}", key=f"view_{w['id']}"):
            st.code(w['data'])
        if st.button(f"Decrypt Wallet #{w['id']}", key=f"dec_{w['id']}"):
            st.code(decrypt_data(w['data']))
        with st.form(f"txform_{w['id']}", clear_on_submit=True):
            num = st.text_input("Transaction Number (digits only)", key=f"txn_{w['id']}")
            if st.form_submit_button("Add Transaction"):
                ok, msg = create_transaction(w["id"], num)
                st.success(msg) if ok else st.error(msg)
        if st.button(f"Show Transactions #{w['id']}", key=f"showtx_{w['id']}"):
            txs = get_transactions(w["id"])
            if txs:
                df = pd.DataFrame(txs, columns=["Ref", "Number", "Date"])
                st.dataframe(df, use_container_width=True)
            else:
                st.info("No transactions recorded.")

def page_upload():
    if not logged_in(): return
    st.subheader("Upload a Secure File")
    f = st.file_uploader("Select File", type=list(ALLOWED_FILES))
    if f:
        ok, msg = validate_file(f)
        if ok:
            st.success(msg)
        else:
            st.error(msg)

def page_logs():
    if not logged_in(): return
    st.subheader("User Activity Logs")
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT action, detail, time FROM logs WHERE user_id=? ORDER BY time DESC", (st.session_state["user_id"],))
    rows = c.fetchall()
    conn.close()
    if rows:
        df = pd.DataFrame(rows, columns=["Action", "Detail", "Timestamp"])
        st.dataframe(df, use_container_width=True)
        buf = BytesIO()
        df.to_excel(buf, index=False, sheet_name="logs")
        buf.seek(0)
        st.download_button("Download Logs", data=buf, file_name="securevault_logs.xlsx")
    else:
        st.info("No activity logs found.")

# -------------------------------
# Utility
# -------------------------------
def logged_in():
    if "user_id" not in st.session_state:
        st.warning("Please log in first.")
        return False
    return True

def logout():
    if "user_id" in st.session_state:
        log_action(st.session_state["user_id"], "logout")
    st.session_state.clear()
    st.success("You have logged out.")
    st.rerun()

# -------------------------------
# Main App
# -------------------------------
def main():
    set_light_theme()
    init_db()
    init_crypto()

    st.markdown("<div class='app-header'><h1>SecureVault — FinTech Demo App</h1></div>", unsafe_allow_html=True)

    pages = ["🏠 Home", "🧾 Register", "🔐 Login", "💼 Wallets", "📁 Upload", "🧩 Logs"]
    cols = st.columns(len(pages))
    active_page = st.session_state.get("active_page", "🏠 Home")

    for i, p in enumerate(pages):
        if cols[i].button(p):
            st.session_state["active_page"] = p
            st.rerun()

    if active_page == "🏠 Home": page_home()
    elif active_page == "🧾 Register": page_register()
    elif active_page == "🔐 Login": page_login()
    elif active_page == "💼 Wallets": page_wallets()
    elif active_page == "📁 Upload": page_upload()
    elif active_page == "🧩 Logs": page_logs()

    if "user_id" in st.session_state:
        st.markdown("---")
        if st.button("🚪 Logout"):
            logout()

if __name__ == "__main__":
    main()
