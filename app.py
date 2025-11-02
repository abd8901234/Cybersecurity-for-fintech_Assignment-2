import os
import re
import time
import sqlite3
import random
import string
import bcrypt
import streamlit as st
import pandas as pd
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet

# ---------------------------
# Configuration
# ---------------------------
DB_FILE = "securepay_data.db"
KEY_FILE = "securepay_secret.key"
ALLOWED_TYPES = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# ---------------------------
# Light UI Theme
# ---------------------------
def apply_theme():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg, #f4f9ff 0%, #e9f3ff 100%);
            color: #002b36;
            font-family: "Poppins", sans-serif;
        }
        .app-card {
            background: #ffffff;
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        h1, h2, h3 {
            color: #003366;
        }
        .stButton>button {
            background-color: #0078ff !important;
            color: white !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background-color: #f9fbfd !important;
            color: #002b36 !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------
# Crypto Setup
# ---------------------------
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
    fernet = Fernet(ensure_key())

def encrypt_data(data: str) -> bytes:
    return fernet.encrypt(data.encode())

def decrypt_data(data: bytes) -> str:
    return fernet.decrypt(data).decode()

# ---------------------------
# Database
# ---------------------------
def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        pw_hash BLOB,
        created TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner INTEGER,
        name TEXT,
        data BLOB,
        created TEXT,
        FOREIGN KEY(owner) REFERENCES users(id))""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid INTEGER,
        action TEXT,
        info TEXT,
        ts TEXT)""")
    conn.commit(); conn.close()

# ---------------------------
# Security Helpers
# ---------------------------
EMAIL_RX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PW_RX = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).{8,}$")

def hash_pw(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt())
def check_pw(p, h): return bcrypt.checkpw(p.encode(), h)
def valid_email(e): return bool(EMAIL_RX.match(e))
def strong_pw(p): return bool(PW_RX.match(p))

def sanitize(txt):
    txt = txt.strip()
    if any(x in txt.lower() for x in [" or ", " and ", "drop ", "--", ";", "=", "insert ", "delete "]):
        raise ValueError("Unsafe input detected.")
    return txt

# ---------------------------
# Audit
# ---------------------------
def log_action(uid, action, info=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute("INSERT INTO logs(uid,action,info,ts) VALUES (?,?,?,?)",
              (uid, action, info, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()

# ---------------------------
# User Management
# ---------------------------
def register_user(username, email, pw):
    try:
        username, email = sanitize(username), sanitize(email)
    except ValueError as e:
        return False, str(e)
    if not valid_email(email): return False, "Invalid email."
    if not strong_pw(pw): return False, "Weak password."
    conn = get_conn(); c = conn.cursor()
    try:
        h = hash_pw(pw)
        c.execute("INSERT INTO users(username,email,pw_hash,created) VALUES(?,?,?,?)",
                  (username, email, h, datetime.utcnow().isoformat()))
        conn.commit(); log_action(None, "register", username)
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "User or email already exists."
    finally:
        conn.close()

def get_user(username):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    r = c.fetchone(); conn.close(); return r

def get_user_by_id(uid):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = c.fetchone(); conn.close(); return r

# ---------------------------
# Wallet Management
# ---------------------------
def add_wallet(uid, name, data):
    try:
        name, data = sanitize(name), sanitize(data)
    except ValueError as e:
        return False, str(e)
    enc = encrypt_data(data)
    conn = get_conn(); c = conn.cursor()
    c.execute("INSERT INTO wallets(owner,name,data,created) VALUES(?,?,?,?)",
              (uid, name, enc, datetime.utcnow().isoformat()))
    conn.commit(); conn.close()
    log_action(uid, "wallet_add", name)
    return True, "Wallet added."

def list_wallets(uid):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM wallets WHERE owner=?", (uid,))
    r = c.fetchall(); conn.close(); return r

# ---------------------------
# File Upload
# ---------------------------
def validate_file(uploaded):
    ext = uploaded.name.split(".")[-1].lower()
    if ext not in ALLOWED_TYPES:
        return False, f".{ext} not allowed."
    if uploaded.size > 5 * 1024 * 1024:
        return False, "File too large (>5MB)."
    return True, "File accepted."

# ---------------------------
# App Pages
# ---------------------------
def page_home():
    st.markdown("<div class='app-card'><h2>Welcome to SecurePay</h2><p>Welcome to SecurePay.</p></div>", unsafe_allow_html=True)

def page_signup():
    st.subheader("Create Account")
    with st.form("signup"):
        u = st.text_input("Username")
        e = st.text_input("Email")
        p1 = st.text_input("Password", type="password")
        p2 = st.text_input("Confirm Password", type="password")
        s = st.form_submit_button("Register")
    if s:
        if p1 != p2:
            st.warning("Passwords do not match.")
        else:
            ok, msg = register_user(u, e, p1)
            st.success(msg) if ok else st.error(msg)

def page_login():
    st.subheader("Sign In")
    with st.form("login"):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        s = st.form_submit_button("Login")
    if s:
        if not u or not p:
            st.warning("Fields required.")
            return
        user = get_user(u)
        if user and check_pw(p, user["pw_hash"]):
            st.session_state["uid"] = user["id"]
            st.session_state["username"] = user["username"]
            log_action(user["id"], "login")
            st.success("Login successful!")
        else:
            st.error("Invalid credentials.")

def page_wallets():
    if not logged_in(): return
    st.subheader("My Wallets")
    with st.form("wform"):
        n = st.text_input("Wallet Name")
        d = st.text_area("Wallet Data")
        s = st.form_submit_button("Add Wallet")
    if s:
        ok, msg = add_wallet(st.session_state["uid"], n, d)
        st.success(msg) if ok else st.error(msg)
    st.divider()
    ws = list_wallets(st.session_state["uid"])
    if not ws:
        st.info("No wallets yet.")
        return
    for w in ws:
        st.markdown(f"**{w['name']}** — {w['created']}")
        col1, col2 = st.columns(2)
        with col1:
            if st.button(f"Decrypt {w['id']}", key=f"dec_{w['id']}"):
                try:
                    st.code(decrypt_data(w["data"]))
                except:
                    st.error("Failed to decrypt.")
        with col2:
            st.code(f"Encrypted blob: {str(w['data'])[:80]}...")

def page_upload():
    if not logged_in(): return
    st.subheader("Upload Secure File")
    f = st.file_uploader("Select a file", type=list(ALLOWED_TYPES))
    if f:
        ok, msg = validate_file(f)
        if ok:
            st.success("Uploaded successfully.")
            st.write({"File": f.name, "Size": f.size})
            log_action(st.session_state["uid"], "file_upload", f.name)
        else:
            st.error(msg)

def page_audit():
    if not logged_in(): return
    st.subheader("Activity Logs")
    uid = st.session_state["uid"]
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT action, info, ts FROM logs WHERE uid=? ORDER BY ts DESC", (uid,))
    rows = c.fetchall(); conn.close()
    if not rows:
        st.info("No logs yet.")
        return
    df = pd.DataFrame(rows, columns=["Action", "Info", "Timestamp"])
    st.dataframe(df, use_container_width=True)
    buf = BytesIO(); df.to_excel(buf, index=False, sheet_name="logs"); buf.seek(0)
    st.download_button("Download Logs", data=buf, file_name="securepay_logs.xlsx")

# ---------------------------
# Utility
# ---------------------------
def logged_in():
    if "uid" not in st.session_state:
        st.warning("Please login first.")
        return False
    return True

def logout():
    if "uid" in st.session_state:
        log_action(st.session_state["uid"], "logout")
    st.session_state.clear()
    st.success("Logged out.")
    time.sleep(1)
    st.rerun()

# ---------------------------
# Main App
# ---------------------------
def main():
    apply_theme()
    init_db(); init_crypto()
    st.sidebar.title("🔐 SecurePay")
    menu = ["Home", "Sign Up", "Login", "Wallets", "Upload", "Logs"]
    page = st.sidebar.radio("Navigation", menu)
    if logged_in():
        st.sidebar.markdown(f"**User:** {st.session_state['username']}**")
        if st.sidebar.button("Logout"):
            logout()
    if page == "Home": page_home()
    elif page == "Sign Up": page_signup()
    elif page == "Login": page_login()
    elif page == "Wallets": page_wallets()
    elif page == "Upload": page_upload()
    elif page == "Logs": page_audit()

if __name__ == "__main__":
    main()
