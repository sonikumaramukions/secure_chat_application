# websocket_server.py
import asyncio
import websockets
import json
import sqlite3
import bcrypt
import os
import secrets
import time

DB_FILE = "chat_users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        cursor.execute("ALTER TABLE users ADD COLUMN token_expiry REAL")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()
    print("[DB] Database initialized.")

def register_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def check_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    record = cursor.fetchone()
    conn.close()
    if record:
        stored_hash = record[0]
        # sqlite may return TEXT as str; bcrypt expects bytes
        if isinstance(stored_hash, str):
            stored_hash = stored_hash.encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
    return False

def set_password_reset_token(username):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cursor.fetchone() is None:
        conn.close()
        return None
    token = secrets.token_hex(32)
    token_hash = bcrypt.hashpw(token.encode('utf-8'), bcrypt.gensalt())
    expiry_time = time.time() + 3600
    cursor.execute("UPDATE users SET reset_token = ?, token_expiry = ? WHERE username = ?", (token_hash, expiry_time, username))
    conn.commit()
    conn.close()
    return token

def reset_password(username, token, new_password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT reset_token, token_expiry FROM users WHERE username = ?", (username,))
    record = cursor.fetchone()
    if not record or not record[0]:
        conn.close()
        return False
    token_hash_db, expiry_time = record
    if time.time() > expiry_time:
        conn.close()
        return False
    # Ensure stored token hash is bytes for bcrypt
    if isinstance(token_hash_db, str):
        token_hash_db = token_hash_db.encode('utf-8')
    if bcrypt.checkpw(token.encode('utf-8'), token_hash_db):
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("UPDATE users SET password_hash = ?, reset_token = NULL, token_expiry = NULL WHERE username = ?", (new_password_hash, username))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

users_online = {}
users_lock = asyncio.Lock()

async def relay(message):
    recipient_username = message.get('recipient')
    if not recipient_username: return
    async with users_lock:
        recipient_websocket = users_online.get(recipient_username)
        if recipient_websocket:
            try:
                # Log ciphertext transmission length when present
                payload_len = 0
                if message.get('type') == 'encrypted_message':
                    payload_len = len(message.get('ciphertext', ''))
                elif message.get('type') == 'encrypted_file':
                    payload_len = len((message.get('payload') or {}).get('data', ''))
                sender_username = message.get('sender', 'unknown')
                if payload_len:
                    print(f"[Ciphertext] from {sender_username} → to {recipient_username} | length: {payload_len}")
                await recipient_websocket.send(json.dumps(message))
            except Exception as e:
                print(f"[FORWARD ERROR] {e}")
        else:
            print(f"[INFO] Recipient '{recipient_username}' is not online.")

async def handler(websocket):
    username = None
    is_authenticated = False
    try:
        while not is_authenticated:
            auth_data = await websocket.recv()
            message = json.loads(auth_data)
            auth_type = message.get('type')
            if auth_type == 'forgot_password':
                req_username = message.get('username')
                reset_token = set_password_reset_token(req_username)
                if reset_token:
                    print("-" * 50)
                    print(f"[PASSWORD RESET] Request for user: {req_username}")
                    print(f"  >> SIMULATED EMAIL: Your reset token is: {reset_token}")
                    print(f"  >> In the app, use command: reset {req_username} {reset_token} <new_password>")
                    print("-" * 50)
                await websocket.send(json.dumps({'type': 'forgot_response', 'success': True, 'message': 'If user exists, reset instructions generated on server console.'}))
                continue
            if auth_type == 'reset_password':
                req_username = message.get('username')
                token = message.get('token')
                new_password = message.get('password')
                if reset_password(req_username, token, new_password):
                    await websocket.send(json.dumps({'type': 'reset_response', 'success': True, 'message': 'Password has been reset. Please log in.'}))
                else:
                    await websocket.send(json.dumps({'type': 'reset_response', 'success': False, 'message': 'Invalid user, token, or token expired.'}))
                continue
            username = message.get('username')
            password = message.get('password')
            if auth_type == 'register':
                if register_user(username, password):
                    is_authenticated = True
                    await websocket.send(json.dumps({'type': 'auth_response', 'success': True}))
                else:
                    await websocket.send(json.dumps({'type': 'auth_response', 'success': False, 'message': 'Username taken.'}))
            elif auth_type == 'login':
                if check_user(username, password):
                    is_authenticated = True
                    await websocket.send(json.dumps({'type': 'auth_response', 'success': True}))
                else:
                    await websocket.send(json.dumps({'type': 'auth_response', 'success': False, 'message': 'Invalid credentials.'}))
        async with users_lock:
            users_online[username] = websocket
        print(f"[AUTH] User '{username}' authenticated.")
        async for message_data in websocket:
            message = json.loads(message_data)
            # Server does not decrypt or inspect plaintext
            await relay(message)
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        async with users_lock:
            if username and username in users_online:
                del users_online[username]
                print(f"[DISCONNECT] User '{username}' offline.")

async def main():
    init_db()
    # Allow larger frames up to ~30 MB (base64 expands by ~33%) to safely carry 25 MB files
    async with websockets.serve(handler, "0.0.0.0", 8765, max_size=35*1024*1024):
        print("[LISTENING] WebSocket server is listening on port 8765...")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
