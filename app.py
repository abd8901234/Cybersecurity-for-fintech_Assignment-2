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

# -------------------------
# Config
# -------------------------
DB = "friend_secure_fintech.db"
KEYFILE = "friend_secret.key"
ALLOWED = {"png", "jpg", "jpeg", "pdf", "csv", "txt"}

# -------------------------
# UI theme (different look)
# -------------------------
def apply_theme():
    st.markdown(
        """
        <style>
        .stApp {
            background: linear-gradient(180deg,#0f1724 0%, #0b1220 40%, #071029 100%);
            color: #e6f7ff;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
        }
        .card {
            background: rgba(20,30,40,0.55);
            border-radius: 14px; padding: 16px;
            border: 1px solid rgba(120,200,255,0.06);
            box-shadow: 0 6px 18px rgba(3,10,22,0.6);
        }
        .primary-btn>button { background: linear-gradient(90deg,#7ef3ff,#6aa6ff); color:#026; font-weight:700; }
        h1, h2, h3 { color: #dffbff; }
        small { color: #a6cfe3; }
        </style>
        """, unsafe_allow_html=True
    )

# -------------------------
# Crypto utilities
# -------------------------
def ensure_key():
    if os.path.exists(KEYFILE):
        with open(KEYFILE, "rb") as f:
            return f.read()
    k = Fernet.generate_key()
    with open(KEYFILE, "wb") as f:
        f.write(k)
    return k

fernet = None
def init_crypto():
    global fernet
    key = ensure_key()
    fernet = Fernet(key)

def enc_text(s: str) -> bytes:
    return fernet.encrypt(s.encode())

def dec_text(b: bytes) -> str:
    return fernet.decrypt(b).decode()

# -------------------------
# DB helpers
# -------------------------
def get_conn():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn(); c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        pw_hash BLOB NOT NULL,
        created TEXT NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner INTEGER NOT NULL,
        name TEXT NOT NULL,
        data BLOB NOT NULL,
        created TEXT NOT NULL,
        FOREIGN KEY(owner) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        tx_ref TEXT NOT NULL,
        tx_number TEXT NOT NULL,
        tx_data BLOB NOT NULL,
        created TEXT NOT NULL,
        FOREIGN KEY(wallet_id) REFERENCES wallets(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid INTEGER,
        action TEXT NOT NULL,
        meta TEXT,
        ts TEXT NOT NULL
    )""")
    conn.commit(); conn.close()

# -------------------------
# Security helpers
# -------------------------
PASSWORD_RX = re.compile(r"^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).*$")
EMAIL_RX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def hash_pw(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_pw(pw: str, h: bytes) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), h)
    except Exception:
        return False

def strong_pw(pw: str) -> bool:
    return bool(PASSWORD_RX.match(pw))

def valid_email(e: str) -> bool:
    return bool(EMAIL_RX.match(e))

def sanitize_input(s: str, maxlen=1500) -> str:
    s = s.strip()
    if len(s) > maxlen:
        st.warning("Input was too long — truncated to safe length.")
        s = s[:maxlen]
    # remove tags
    s = re.sub(r"(?i)<.*?>", "", s)
    # block obvious SQL tokens
    lowered = s.lower()
    for tok in ["--", ";", "/*", "*/", " or ", " and ", "drop ", "delete ", "insert ", "update ", "="]:
        if tok in lowered:
            raise ValueError("Disallowed characters or tokens in input.")
    return s

def suspicious_input(s: str) -> bool:
    # checks for SQL-like or injection-ish content (for login)
    return bool(re.search(r"('|--|;|\bOR\b|\bAND\b|\bDROP\b|\bSELECT\b)", s, re.IGNORECASE))

# -------------------------
# Audit logger
# -------------------------
def audit(uid, action, meta=None):
    try:
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO audit(uid, action, meta, ts) VALUES (?,?,?,?)",
                  (uid, action, meta, datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
    except Exception:
        pass

# -------------------------
# User operations
# -------------------------
def register_user(username, email, password):
    try:
        username = sanitize_input(username, maxlen=100)
        email = sanitize_input(email, maxlen=200)
    except ValueError as e:
        return False, str(e)
    if not username or not email or not password:
        return False, "All fields required."
    if not valid_email(email):
        return False, "Invalid email address."
    if not strong_pw(password):
        return False, "Password too weak."
    try:
        conn = get_conn(); c = conn.cursor()
        h = hash_pw(password)
        c.execute("INSERT INTO users(username,email,pw_hash,created) VALUES (?,?,?,?)",
                  (username, email, h, datetime.utcnow().isoformat()))
        conn.commit()
        uid = c.lastrowid
        conn.close()
        audit(uid, "register", username)
        return True, "Registered successfully."
    except sqlite3.IntegrityError:
        return False, "Username or email already taken."
    except Exception:
        return False, "Registration failed."

def get_user_by_username(username):
    try:
        username = sanitize_input(username, maxlen=100)
    except ValueError:
        return None
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    r = c.fetchone(); conn.close(); return r

def get_user(uid):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    r = c.fetchone(); conn.close(); return r

# -------------------------
# Wallets & transactions
# -------------------------
def add_wallet(owner, name, data_plain):
    try:
        name = sanitize_input(name, maxlen=200)
        data_plain = sanitize_input(data_plain, maxlen=2000)
    except ValueError as e:
        return False, str(e)
    try:
        enc = enc_text(data_plain)
        conn = get_conn(); c = conn.cursor()
        c.execute("INSERT INTO wallets(owner,name,data,created) VALUES (?,?,?,?)",
                  (owner, name, enc, datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
        audit(owner, "wallet_create", name)
        return True, "Wallet added."
    except Exception:
        return False, "Could not create wallet."

def list_wallets(owner):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT id,name,created FROM wallets WHERE owner=?", (owner,))
    rows = c.fetchall(); conn.close(); return rows

def view_wallet_blob(wallet_id):
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT data FROM wallets WHERE id=?", (wallet_id,))
    r = c.fetchone(); conn.close()
    return r["data"] if r else None



# -------------------------
# File validation
# -------------------------
def validate_file(uploaded):
    name = uploaded.name
    ext = name.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED:
        return False, f".{ext} not allowed"
    if uploaded.size > 5 * 1024 * 1024:
        return False, "File too large (>5MB)"
    return True, "OK"

# -------------------------
# App UI pages (different flows and UI)
# -------------------------
def page_home():
    st.title("FinShield — Secure FinTech Prototype")
    st.markdown("A secure demo for CY4053. Confidential data encrypted at rest. Audit logs maintained.")
    st.divider()
    st.markdown("**Quick actions**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Register"): st.experimental_set_query_params(page="register")
    with col2:
        if st.button("Login"): st.experimental_set_query_params(page="login")
    with col3:
        if st.button("Wallets"): st.experimental_set_query_params(page="wallets")

def page_register():
    st.header("Create an account")
    with st.form("regf"):
        username = st.text_input("Username")
        email = st.text_input("Email")
        pw = st.text_input("Password", type="password")
        pw2 = st.text_input("Confirm password", type="password")
        submit = st.form_submit_button("Sign up")
    if submit:
        if pw != pw2:
            st.warning("Passwords do not match.")
        else:
            ok, msg = register_user(username, email, pw)
            if ok:
                st.success(msg); st.info("Now log in from Login page.")
            else:
                st.error(msg)

def page_login():
    st.header("Access account")
    if "lock_until" not in st.session_state:
        st.session_state["lock_until"] = 0
    if time.time() < st.session_state["lock_until"]:
        st.error(f"Account actions locked. Try again in {int(st.session_state['lock_until'] - time.time())}s")
        return
    with st.form("logf"):
        username = st.text_input("Username")
        pw = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
    if submitted:
        if not username.strip() or not pw.strip():
            st.warning("Both fields required.")
            return
        if suspicious_input(username):
            st.error("⚠️ Unsafe input detected. Remove special characters or SQL keywords.")
            audit(None, "login_block", username)
            return
        user = get_user_by_username(username)
        if user and check_pw(pw, user["pw_hash"]):
            st.session_state["uid"] = user["id"]
            st.session_state["username"] = user["username"]
            st.session_state["failed"] = 0
            st.success("Welcome — logged in.")
            audit(user["id"], "login")
        else:
            st.session_state["failed"] = st.session_state.get("failed", 0) + 1
            left = 5 - st.session_state["failed"]
            if left > 0:
                st.error(f"Invalid credentials. {left} attempts left.")
            else:
                st.session_state["lock_until"] = time.time() + 60
                st.error("Too many attempts. Locked for 1 minute.")
                audit(None, "lockout", username)

def page_profile():
    st.header("Profile & Account")
    if not require_login():
        st.warning("Please log in.")
        return
    uid = st.session_state["uid"]
    user = get_user(uid)
    st.write(f"**Username:** {user['username']}"); st.write(f"**Email:** {user['email']}")
    st.divider()
    with st.form("chgmail"):
        newmail = st.text_input("New email")
        if st.form_submit_button("Update email"):
            ok, msg = update_user_email(uid, newmail)
            st.success(msg) if ok else st.error(msg)
    st.divider()
    with st.form("pwchange"):
        old = st.text_input("Old password", type="password")
        new = st.text_input("New password", type="password")
        conf = st.text_input("Confirm new", type="password")
        if st.form_submit_button("Change password"):
            if new != conf: st.warning("New passwords mismatch.")
            else:
                ok, msg = change_user_password(uid, old, new)
                st.success(msg) if ok else st.error(msg)

def page_wallets():
    st.header("Wallets & Transactions")
    if not require_login():
        st.warning("Login required.")
        return
    uid = st.session_state["uid"]
    st.subheader("Create wallet")
    with st.form("wallet_add"):
        wname = st.text_input("Wallet name")
        wdata = st.text_area("Private content")
        add = st.form_submit_button("Create")
    if add:
        ok, msg = add_wallet(uid, wname, wdata)
        st.success(msg) if ok else st.error(msg)

    st.divider()
    wallets = list_wallets(uid)
    for w in wallets:
        wid = w["id"]; name = w["name"]; created = w["created"]
        st.markdown(f"**{name}** — created {created}")
        col1, col2, col3 = st.columns([1,1,2])
        with col1:
            if st.button("Show (decrypted)", key=f"dv_{wid}"):
                blob = view_wallet_blob(wid)
                try:
                    st.code(dec_text(blob))
                except Exception:
                    st.error("Unable to decrypt (or unauthorized).")
        with col2:
            if st.button("Show raw blob", key=f"raw_{wid}"):
                blob = view_wallet_blob(wid)
                st.code(str(blob)[:200] + " ... (blob)") if blob else st.info("No data")
        with col3:
            with st.form(f"txform_{wid}", clear_on_submit=True):
                num = st.text_input("Transaction number (digits only)", key=f"txnum_{wid}")
                submit_tx = st.form_submit_button("Add Transaction")
            if submit_tx:
                ok, msg = add_transaction(wid, num)
                st.success(msg) if ok else st.error(msg)

        if st.button("View transactions", key=f"vtx_{wid}"):
            txs = get_transactions(wid)
            if not txs: st.info("No transactions yet.")
            else:
                df = pd.DataFrame(txs, columns=["Ref","Number","Created"])
                st.dataframe(df, use_container_width=True)

def page_files():
    st.header("Upload files (validated)")
    if not require_login():
        st.warning("Login required.")
        return
    f = st.file_uploader("Choose file", type=list(ALLOWED))
    if f:
        ok,msg = validate_file(f)
        if ok:
            st.success("Accepted.")
            st.write({"name": f.name, "size": f.size})
            audit(st.session_state["uid"], "file_upload", f.name)
        else:
            st.error(msg)

def page_audit():
    st.header("Audit & Export")
    if not require_login():
        st.warning("Login required.")
        return
    uid = st.session_state["uid"]
    conn = get_conn(); c = conn.cursor()
    c.execute("SELECT id, uid, action, meta, ts FROM audit WHERE uid=? ORDER BY ts DESC LIMIT 500", (uid,))
    rows = c.fetchall(); conn.close()
    if not rows:
        st.info("No logs.")
        return
    df = pd.DataFrame(rows, columns=["ID","User","Action","Meta","Timestamp"])
    st.dataframe(df, use_container_width=True)
    buf = BytesIO(); df.to_excel(buf, index=False, sheet_name="audit"); buf.seek(0)
    st.download_button("Download logs", data=buf, file_name="audit_logs_friend.xlsx")

def page_error_test():
    st.header("Controlled error test")
    if st.button("Trigger safe error"):
        try:
            _ = 1/0
        except Exception:
            st.error("Controlled error handled. No stack traces shown.")
            audit(st.session_state.get("uid"), "error_test")

# -------------------------
# Account helpers (profile)
# -------------------------
def update_user_email(uid, new):
    if not new or not valid_email(new): return False, "Invalid email."
    try:
        conn = get_conn(); c = conn.cursor()
        c.execute("UPDATE users SET email=? WHERE id=?", (new, uid))
        conn.commit(); conn.close(); audit(uid, "email_change", new); return True, "Email updated."
    except sqlite3.IntegrityError:
        return False, "Email already used."
    except Exception:
        return False, "Update failed."

def change_user_password(uid, old, new):
    if not new or not strong_pw(new): return False, "Weak new password."
    user = get_user(uid)
    if not user or not check_pw(old, user["pw_hash"]): return False, "Old password incorrect."
    try:
        conn = get_conn(); c = conn.cursor()
        c.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_pw(new), uid))
        conn.commit(); conn.close(); audit(uid, "pw_change"); return True, "Password changed."
    except Exception:
        return False, "Password update failed."

# -------------------------
# Utilities
# -------------------------
def require_login() -> bool:
    return "uid" in st.session_state and st.session_state["uid"]

def logout():
    if "uid" in st.session_state:
        audit(st.session_state.get("uid"), "logout")
    st.session_state.clear()
    st.success("Logged out.")
    time.sleep(0.8)
    st.experimental_rerun()

# -------------------------
# App routing
# -------------------------
def main():
    apply_theme()
    init_db(); init_crypto()

    st.sidebar.markdown("<div class='card'><h3>FinShield</h3><small>Secure FinTech Demo</small></div>", unsafe_allow_html=True)
    menu = ["Home","Register","Login","Wallets","Files","Audit","Profile","Error Test"]
    choice = st.sidebar.selectbox("Navigate", menu)

    if require_login():
        st.sidebar.markdown(f"**User:** {st.session_state['username']}")
        if st.sidebar.button("Logout"):
            logout()

    if choice == "Home": page_home()
    elif choice == "Register": page_register()
    elif choice == "Login": page_login()
    elif choice == "Wallets": page_wallets()
    elif choice == "Files": page_files()
    elif choice == "Audit": page_audit()
    elif choice == "Profile": page_profile()
    elif choice == "Error Test": page_error_test()

if __name__ == "__main__":
    main()
