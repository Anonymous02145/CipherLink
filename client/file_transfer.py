from include import *

class FileTransferProtocol:
    def __init__(self):
        self.chunk_size = 8192
        self.transfers = {}

    def prepare_file_transfer(self, file_path: str) -> Dict[str, Any]:
        try:
            if not os.path.exists(file_path):
                return None

            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            file_hash = self._calculate_file_hash(file_path)

            transfer_id = secrets.token_hex(16)
            self.transfers[transfer_id] = {
                "file_path": file_path,
                "file_size": file_size,
                "file_name": file_name,
                "file_hash": file_hash,
                "chunks_sent": 0,
                "total_chunks": (file_size + self.chunk_size - 1) // self.chunk_size,
                "status": "ready",
            }

            return {
                "transfer_id": transfer_id,
                "file_name": file_name,
                "file_size": file_size,
                "file_hash": file_hash,
                "total_chunks": self.transfers[transfer_id]["total_chunks"],
            }
        except Exception:
            return None

    def encrypt_file_chunk(
        self, transfer_id: str, chunk_index: int, key: bytes
    ) -> Optional[bytes]:
        try:
            if transfer_id not in self.transfers:
                return None

            transfer = self.transfers[transfer_id]
            chunk_size = self.chunk_size
            offset = chunk_index * chunk_size

            with open(transfer["file_path"], "rb") as f:
                f.seek(offset)
                chunk_data = f.read(chunk_size)

            if not chunk_data:
                return None

            chunk_envelope = {
                "transfer_id": transfer_id,
                "chunk_index": chunk_index,
                "total_chunks": transfer["total_chunks"],
                "data": base64.b64encode(chunk_data).decode(),
                "timestamp": time.time(),
            }

            serialized_chunk = json.dumps(chunk_envelope)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, serialized_chunk.encode(), b"")

            return nonce + ciphertext

        except Exception:
            return None

    def decrypt_file_chunk(
        self, encrypted_chunk: bytes, key: bytes
    ) -> Optional[Dict[str, Any]]:
        try:
            if len(encrypted_chunk) < 28:
                return None

            nonce = encrypted_chunk[:12]
            ciphertext = encrypted_chunk[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, b"")
            chunk_envelope = json.loads(decrypted_data.decode())

            required_fields = ["transfer_id", "chunk_index", "total_chunks", "data"]
            if not all(field in chunk_envelope for field in required_fields):
                return None

            return chunk_envelope

        except Exception:
            return None

    def _calculate_file_hash(self, file_path: str) -> str:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
