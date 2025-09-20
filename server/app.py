from hmac import digest_size
from flask import Flask, request, jsonify
import sqlite3
from cryptography.hazmat.primitives import hashes


app = Flask(__name__)

def init_db():
    conn = sqlite3.connect("register.db")
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_hash TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def get_db():

    connection = sqlite3.connect("register.db")

    connection.row_factory = sqlite3.Row
    return connection

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    user = data['username']
    public_key = data['key']

    conn = get_db()
    cursor = conn.cursor

    digester = hashes.Hash(hashes.SHA256())

    digester.update(user.encode())
    user_hash = digester.finalize()

    conn.execute(
        "INSERT or REPLACE INTO users (username_hash, public_key) VALUES (?, ?)",
        (user_hash.hex(), public_key)
    )

    conn.commit()
    conn.close()

    print(f"Data: {data}")

    response_data = {"status" : "registered"}
    return jsonify(response_data)

@app.route('/get_key', methods=['GET'])
def get_hash_key():
    u = request.get_json()

    username_hash = u['username_hash']

    if not username_hash:
        return jsonify({"Error ": "   username_hash parameter required"}), 400

    conn = sqlite3.connect("register.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username_hash = ?", (username_hash,))
    fetch = cursor.fetchone()

    key = fetch[2]

    conn.commit()
    conn.close()
    if fetch:
        return jsonify({"Public_Key": key})

    else:
        return jsonify({"Error": "User Not Found"}), 404


init_db()
app.run(host='0.0.0.0',port=8000, debug=True)
