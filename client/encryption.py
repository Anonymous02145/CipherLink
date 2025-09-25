from include import *

class E2EEncryptionEngine:
    def __init__(self):
        self.message_counter = 0
        self.session_keys = {}
        self.pending_messages = Queue()

    def derive_session_key(self, shared_secret: bytes, session_id: str) -> bytes:
        try:
            info = f"p2p_session_{session_id}".encode()
            hkdf = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), info=info
            )
            return hkdf.derive(shared_secret)
        except Exception:
            return None

    def encrypt_message_advanced(
        self, plaintext: str, key: bytes, message_id: str
    ) -> Optional[bytes]:
        try:
            message_data = {
                "data": plaintext,
                "timestamp": time.time(),
                "msg_id": message_id,
                "version": "1.0",
                "padding": base64.b64encode(os.urandom(MESSAGE_PADDING_SIZE)).decode(),
            }

            serialized_data = json.dumps(message_data, separators=(",", ":"))
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, serialized_data.encode(), b"")

            return nonce + ciphertext

        except Exception:
            return None

    def decrypt_message_advanced(
        self, encrypted_data: bytes, key: bytes
    ) -> Optional[Dict[str, Any]]:
        try:
            if len(encrypted_data) < 28:
                return None

            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, b"")
            message_data = json.loads(decrypted_data.decode())

            if not all(k in message_data for k in ["data", "timestamp", "msg_id"]):
                return None

            if time.time() - message_data["timestamp"] > 300:
                return None

            return message_data

        except Exception:
            return None
