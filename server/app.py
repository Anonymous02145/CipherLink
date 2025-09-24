from flask import Flask, request, jsonify
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac
import time
import threading
import os
import secrets
import hashlib

app = Flask(__name__)

# ========== SECURITY CONFIGURATION ==========
MAX_REQUESTS_PER_MINUTE = 50  # Increased for multiple connections
REQUEST_TIMEOUT = 120
CLEANUP_INTERVAL = 30

request_counts = {}
rate_limit_lock = threading.Lock()

# ========== DATABASE SETUP ==========
def init_db():
    conn = sqlite3.connect("register.db", check_same_thread=False)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_hash TEXT UNIQUE NOT NULL,
            peer_id TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            session_token TEXT,
            token_expiry TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_connections INTEGER DEFAULT 0,
            active_since TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_users_session ON users(session_token)
    ''')

    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_users_peer_id ON users(peer_id)
    ''')

    # Create connection logs table for debugging
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS connection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            initiator_hash TEXT NOT NULL,
            target_hash TEXT NOT NULL,
            connection_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            success BOOLEAN DEFAULT FALSE,
            error_message TEXT
        )
    ''')

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect("register.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

# ========== UTILITIES ==========
def generate_session_token():
    return secrets.token_urlsafe(32)

def anonymous_rate_limit(anonymous_id):
    current_minute = int(time.time() // 60)
    key = f"{anonymous_id}:{current_minute}"

    with rate_limit_lock:
        if key not in request_counts:
            request_counts[key] = 0

        request_counts[key] += 1

        if request_counts[key] > MAX_REQUESTS_PER_MINUTE:
            return False

        old_keys = [k for k in request_counts.keys()
                   if int(k.split(':')[-1]) < current_minute - 5]
        for k in old_keys:
            del request_counts[k]

    return True

def validate_session(username_hash, session_token):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT token_expiry FROM users
        WHERE username_hash = ? AND session_token = ?
    ''', (username_hash, session_token))

    user = cursor.fetchone()

    if user:
        # Update last seen
        cursor.execute('''
            UPDATE users SET last_seen = CURRENT_TIMESTAMP
            WHERE username_hash = ? AND session_token = ?
        ''', (username_hash, session_token))
        conn.commit()

    conn.close()

    if not user:
        return False

    try:
        expiry = time.mktime(time.strptime(user['token_expiry'], '%Y-%m-%d %H:%M:%S'))
        return time.time() < expiry
    except:
        return False

def log_connection_attempt(initiator_hash, target_hash, success=False, error_msg=None):
    """Log connection attempts for debugging"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO connection_logs (initiator_hash, target_hash, success, error_message)
            VALUES (?, ?, ?, ?)
        ''', (initiator_hash[:16], target_hash[:16], success, error_msg))
        conn.commit()
        conn.close()
    except:
        pass  # Don't let logging break the main flow

# ========== CONNECTION MANAGEMENT ==========
connection_requests = {}
user_listening_ports = {}  # Store each user's listening port
user_connection_counts = {}  # Track connection counts per user

LOCK = threading.Lock()

def cleanup_ephemeral_data():
    while True:
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()

        with LOCK:
            # Clean old connection requests
            expired_requests = [k for k, v in connection_requests.items()
                              if now - v['timestamp'] > 300]
            for k in expired_requests:
                del connection_requests[k]

            # Clean old port mappings (5 minutes for more active cleanup)
            expired_ports = [k for k, v in user_listening_ports.items()
                           if now - v['timestamp'] > 300]
            for k in expired_ports:
                del user_listening_ports[k]
                if k in user_connection_counts:
                    del user_connection_counts[k]

        print(f"[SERVER] Cleanup: {len(user_listening_ports)} active listeners")

cleanup_thread = threading.Thread(target=cleanup_ephemeral_data, daemon=True)
cleanup_thread.start()

# ========== ROUTES ==========
@app.before_request
def anonymous_security():
    if request.method == 'POST' and request.json:
        content_hash = hashlib.blake2b(
            str(request.json).encode(),
            digest_size=16
        ).hexdigest()

        if not anonymous_rate_limit(content_hash):
            return jsonify({"error": "Rate limit exceeded"}), 429

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or 'username_hash' not in data or 'public_key' not in data or 'peer_id' not in data:
            return jsonify({"error": "Missing required fields"}), 400

        username_hash = data['username_hash']
        public_key = data['public_key']
        peer_id = data['peer_id']

        if len(username_hash) != 64 or len(public_key) != 64 or len(peer_id) != 64:
            return jsonify({"error": "Invalid parameter lengths"}), 400

        session_token = generate_session_token()
        token_expiry = time.time() + 86400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO users
            (username_hash, peer_id, public_key, session_token, token_expiry, active_since)
            VALUES (?, ?, ?, ?, datetime(?, 'unixepoch'), CURRENT_TIMESTAMP)
        ''', (username_hash, peer_id, public_key, session_token, token_expiry))

        conn.commit()
        conn.close()

        print(f"[SERVER] User registered: {username_hash[:16]}... (Peer: {peer_id[:16]}...)")

        return jsonify({
            "status": "registered",
            "session_token": session_token,
            "expires_in": 86400
        })

    except sqlite3.IntegrityError as e:
        print(f"[SERVER] Registration integrity error: {e}")
        return jsonify({"error": "User already exists"}), 400
    except Exception as e:
        print(f"[SERVER] Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/authenticate', methods=['POST'])
def authenticate():
    try:
        data = request.get_json()
        if not data or 'username_hash' not in data or 'session_token' not in data:
            return jsonify({"error": "Missing credentials"}), 400

        username_hash = data['username_hash']
        session_token = data['session_token']

        if validate_session(username_hash, session_token):
            return jsonify({"status": "authenticated"})
        else:
            return jsonify({"error": "Invalid session"}), 401

    except Exception as e:
        print(f"[SERVER] Authentication error: {e}")
        return jsonify({"error": "Authentication failed"}), 500

@app.route('/get_key', methods=['GET'])
def get_key():
    try:
        username_hash = request.args.get('username_hash')
        session_token = request.args.get('session_token')

        if not username_hash or not session_token:
            return jsonify({"error": "Missing parameters"}), 400

        if not validate_session(username_hash, session_token):
            return jsonify({"error": "Invalid session"}), 401

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT public_key, peer_id FROM users WHERE username_hash = ?", (username_hash,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return jsonify({
                "public_key": user['public_key'],
                "peer_id": user['peer_id']
            })
        else:
            return jsonify({"error": "User not found"}), 404

    except Exception as e:
        print(f"[SERVER] Key retrieval error: {e}")
        return jsonify({"error": "Key retrieval failed"}), 500

@app.route('/set_listening_port', methods=['POST'])
def set_listening_port():
    """Set the port where user is listening for incoming connections"""
    try:
        data = request.get_json()
        if not data or 'username_hash' not in data or 'session_token' not in data or 'port' not in data:
            return jsonify({"error": "Missing required fields"}), 400

        username_hash = data['username_hash']
        session_token = data['session_token']
        port = data['port']

        if not isinstance(port, int) or port < 1024 or port > 65535:
            return jsonify({"error": "Invalid port number"}), 400

        if not validate_session(username_hash, session_token):
            return jsonify({"error": "Invalid session"}), 401

        with LOCK:
            user_listening_ports[username_hash] = {
                'port': port,
                'timestamp': time.time()
            }
            # Initialize connection count if not exists
            if username_hash not in user_connection_counts:
                user_connection_counts[username_hash] = 0

        print(f"[SERVER] User {username_hash[:16]}... listening on port {port}")
        return jsonify({"status": "port_set", "port": port})

    except Exception as e:
        print(f"[SERVER] Set port error: {e}")
        return jsonify({"error": "Failed to set port"}), 500

@app.route('/request_connection', methods=['POST'])
def request_connection():
    """Initiator requests connection to recipient"""
    try:
        data = request.get_json()
        required_fields = ['username_hash', 'target_username_hash', 'session_token']
        if not data or any(field not in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        initiator_hash = data['username_hash']
        target_hash = data['target_username_hash']
        session_token = data['session_token']

        if not validate_session(initiator_hash, session_token):
            log_connection_attempt(initiator_hash, target_hash, False, "Invalid session")
            return jsonify({"error": "Invalid session"}), 401

        if initiator_hash == target_hash:
            log_connection_attempt(initiator_hash, target_hash, False, "Self connection attempt")
            return jsonify({"error": "Cannot connect to yourself"}), 400

        current_time = time.time()

        with LOCK:
            # Get initiator info
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT peer_id, public_key FROM users WHERE username_hash = ?", (initiator_hash,))
            initiator = cursor.fetchone()
            cursor.execute("SELECT peer_id, public_key FROM users WHERE username_hash = ?", (target_hash,))
            target = cursor.fetchone()
            conn.close()

            if not initiator:
                log_connection_attempt(initiator_hash, target_hash, False, "Initiator not found")
                return jsonify({"error": "Initiator not found"}), 404

            if not target:
                log_connection_attempt(initiator_hash, target_hash, False, "Target user not found")
                return jsonify({"error": "Target user not found"}), 404

            # Check if target is listening
            if target_hash not in user_listening_ports:
                log_connection_attempt(initiator_hash, target_hash, False, "Target user offline")
                return jsonify({"error": "Target user is not online"}), 404

            target_port = user_listening_ports[target_hash]['port']

            # Update connection counts
            user_connection_counts[initiator_hash] = user_connection_counts.get(initiator_hash, 0) + 1
            user_connection_counts[target_hash] = user_connection_counts.get(target_hash, 0) + 1

            # Create connection info for both parties
            connection_info = {
                "status": "connection_ready",
                "initiator_peer_id": initiator['peer_id'],
                "initiator_public_key": initiator['public_key'],
                "target_peer_id": target['peer_id'],
                "target_public_key": target['public_key'],
                "target_listening_port": target_port,
                "timestamp": current_time,
                "connection_id": f"{initiator_hash[:8]}_{target_hash[:8]}_{int(current_time)}"
            }

            log_connection_attempt(initiator_hash, target_hash, True, None)
            print(f"[SERVER] Connection ready: {initiator_hash[:16]}... -> {target_hash[:16]}... on port {target_port}")

            return jsonify(connection_info)

    except Exception as e:
        print(f"[SERVER] Connection request error: {e}")
        log_connection_attempt(initiator_hash if 'initiator_hash' in locals() else 'unknown',
                             target_hash if 'target_hash' in locals() else 'unknown',
                             False, str(e))
        return jsonify({"error": "Connection request failed"}), 500

@app.route('/discover_online', methods=['POST'])
def discover_online():
    """Discover online users - only return peers that are actively listening"""
    try:
        data = request.get_json()
        if not data or 'username_hash' not in data or 'session_token' not in data:
            return jsonify({"error": "Missing credentials"}), 400

        username_hash = data['username_hash']
        session_token = data['session_token']

        if not validate_session(username_hash, session_token):
            return jsonify({"error": "Invalid session"}), 401

        with LOCK:
            online_users = []
            conn = get_db()
            cursor = conn.cursor()

            # Only include users who are actively listening (have port info)
            for user_hash, port_info in user_listening_ports.items():
                if user_hash != username_hash:  # Exclude self
                    # Verify the port info is recent (within last 10 minutes)
                    if time.time() - port_info['timestamp'] < 600:
                        cursor.execute("SELECT peer_id FROM users WHERE username_hash = ?", (user_hash,))
                        user = cursor.fetchone()
                        if user:
                            online_users.append({
                                "peer_id": user['peer_id'],
                                "username_hash": user_hash,
                                "listening_port": port_info['port'],
                                "active_connections": user_connection_counts.get(user_hash, 0),
                                "last_seen": port_info['timestamp']
                            })

            conn.close()

        print(f"[SERVER] Discovery request from {username_hash[:16]}..., found {len(online_users)} active users")
        return jsonify({
            "online_users": online_users,
            "total_online": len(online_users)
        })

    except Exception as e:
        print(f"[SERVER] Discovery error: {e}")
        return jsonify({"error": "Discovery failed"}), 500

@app.route('/update_connection_count', methods=['POST'])
def update_connection_count():
    """Update user's connection count"""
    try:
        data = request.get_json()
        if not data or 'username_hash' not in data or 'session_token' not in data or 'connection_count' not in data:
            return jsonify({"error": "Missing required fields"}), 400

        username_hash = data['username_hash']
        session_token = data['session_token']
        connection_count = data['connection_count']

        if not validate_session(username_hash, session_token):
            return jsonify({"error": "Invalid session"}), 401

        with LOCK:
            if username_hash in user_listening_ports:
                user_connection_counts[username_hash] = max(0, int(connection_count))

        return jsonify({"status": "updated"})

    except Exception as e:
        print(f"[SERVER] Connection count update error: {e}")
        return jsonify({"error": "Update failed"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    with LOCK:
        active_users = len(user_listening_ports)
        total_connections = sum(user_connection_counts.values())

    return jsonify({
        "status": "operational",
        "timestamp": time.time(),
        "active_users": active_users,
        "total_connections": total_connections
    })

@app.route('/debug/state', methods=['GET'])
def debug_state():
    """Debug endpoint to see server state"""
    with LOCK:
        user_states = {}
        for user_hash, port_info in user_listening_ports.items():
            user_states[user_hash[:16]] = {
                'port': port_info['port'],
                'connections': user_connection_counts.get(user_hash, 0),
                'last_seen': port_info['timestamp']
            }

        return jsonify({
            "online_users": user_states,
            "total_users": len(user_listening_ports),
            "total_connections": sum(user_connection_counts.values())
        })

@app.route('/debug/connections', methods=['GET'])
def debug_connections():
    """Show recent connection attempts"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM connection_logs
            ORDER BY connection_time DESC
            LIMIT 20
        ''')
        logs = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify({"recent_connections": logs})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def sanitize_database():
    """Clean up old data"""
    while True:
        time.sleep(3600)  # Run every hour
        try:
            conn = get_db()
            cursor = conn.cursor()

            # Remove old users (inactive for more than 24 hours)
            cursor.execute('DELETE FROM users WHERE last_seen < datetime("now", "-1 day")')
            removed_users = cursor.rowcount

            # Clean old connection logs (older than 7 days)
            cursor.execute('DELETE FROM connection_logs WHERE connection_time < datetime("now", "-7 days")')
            removed_logs = cursor.rowcount

            conn.commit()
            conn.close()

            print(f"[SERVER] Database cleaned: {removed_users} users, {removed_logs} logs removed")
        except Exception as e:
            print(f"[SERVER] Sanitization error: {e}")

sanitize_thread = threading.Thread(target=sanitize_database, daemon=True)
sanitize_thread.start()

def print_status():
    """Print server status periodically"""
    while True:
        time.sleep(60)  # Every minute
        with LOCK:
            active_users = len(user_listening_ports)
            total_connections = sum(user_connection_counts.values())
        print(f"[SERVER] Status: {active_users} active users, {total_connections} total connections")

status_thread = threading.Thread(target=print_status, daemon=True)
status_thread.start()

if __name__ == '__main__':
    init_db()
    print("[SERVER] Starting enhanced secure P2P signaling server on port 8000...")
    print("[SERVER] Features: Multi-peer connections, Public key verification, Connection logging")
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)
