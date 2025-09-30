from .include import *

class ConnectionValidator:
    def __init__(self):
        self.connection_metrics = {}
        self.validation_lock = threading.Lock()

    def validate_connection_integrity(
        self, connection_id: str, public_key: str
    ) -> bool:
        if not connection_id or not public_key:
            print("[-] Validation error: Invalid inputs.")
            return False
        try:
            with self.validation_lock:
                if connection_id in self.connection_metrics:
                    stored_key = self.connection_metrics[connection_id].get(
                        "public_key"
                    )
                    if stored_key and stored_key != public_key:
                        print(
                            f"[!] Security Alert: Key change detected for connection {connection_id}"
                        )
                        return False

                self.connection_metrics[connection_id] = {
                    "public_key": public_key,
                    "last_validated": time.time(),
                    "validation_count": self.connection_metrics.get(
                        connection_id, {}
                    ).get("validation_count", 0)
                    + 1,
                }

                return True
        except Exception as val_err:
            print(f"[-] Validation error: {val_err}")
            return False
