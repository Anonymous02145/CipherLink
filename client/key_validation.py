class KeyValidator:
    def validate(self, self_key, peer_key):
        try:
            if self_key == peer_key:
                return True
            else:
                return False
        except Exception as e:
            raise ValueError(f"Key validation failed: {e}")
