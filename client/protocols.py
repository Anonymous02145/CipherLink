from .encryption import *
from .traffic_manager import *

class SecureMessageProtocol:
    processed_msg_ids = set()

    def __init__(self):
        self.encryption_engine = E2EEncryptionEngine()
        self.traffic_manager = AnonymousTrafficManager()

    @staticmethod
    def encrypt_message(
        plaintext: str, key: bytes, associated_data: bytes = b""
    ) -> Optional[bytes]:
        if not plaintext or not key or len(key) != 32:
            print(
                "[-] Encryption error: Invalid input (empty message or wrong key length)."
            )
            return None
        try:
            current_time = int(time.time())
            entropy = os.urandom(8)
            message_id = hashlib.sha256(
                plaintext.encode() + entropy + str(current_time).encode()
            ).hexdigest()[:16]

            message_envelope = {
                "content": plaintext,
                "timestamp": time.time(),
                "message_id": message_id,
                "version": "secure_v1",
            }

            serialized_message = json.dumps(message_envelope, separators=(",", ":"))
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(
                nonce, serialized_message.encode(), associated_data
            )

            return nonce + ciphertext

        except ValueError as ve:
            print(f"[-] Encryption error (invalid key/nonce): {ve}")
            return None
        except Exception as enc_err:
            print(f"[-] Unexpected encryption failure: {enc_err}")
            return None

    @staticmethod
    def decrypt_message(
        encrypted_data: bytes, key: bytes, associated_data: bytes = b""
    ) -> Optional[str]:
        if not encrypted_data or len(encrypted_data) < 28 or not key or len(key) != 32:
            print(
                "[-] Decryption error: Invalid input (too short or wrong key length)."
            )
            return None
        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, associated_data)
            message_envelope = json.loads(decrypted_data.decode())

            required_fields = ["content", "timestamp", "message_id"]
            if not all(field in message_envelope for field in required_fields):
                print("[-] Decryption error: Missing required fields in envelope.")
                return None

            msg_id = message_envelope["message_id"]

            if len(SecureMessageProtocol.processed_msg_ids) > 1000:
                recent_ids = list(SecureMessageProtocol.processed_msg_ids)[-500:]
                SecureMessageProtocol.processed_msg_ids.clear()
                SecureMessageProtocol.processed_msg_ids.update(recent_ids)

            if msg_id in SecureMessageProtocol.processed_msg_ids:
                print("[-] Decryption warning: Possible replay attack (duplicate ID).")
                return None
            SecureMessageProtocol.processed_msg_ids.add(msg_id)

            current_time = time.time()
            if abs(current_time - message_envelope["timestamp"]) > 600:
                print(
                    "[-] Decryption error: Message timestamp invalid (clock skew or expired)."
                )
                return None

            return message_envelope["content"]

        except json.JSONDecodeError as json_err:
            print(f"[-] Decryption error: Invalid JSON in envelope: {json_err}")
            return None
        except ValueError as dec_ve:
            print(f"[-] Decryption error (auth failure/invalid nonce): {dec_ve}")
            return None
        except Exception as dec_err:
            print(f"[-] Unexpected decryption failure: {dec_err}")
            return None
