from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import requests

class Client:
    def __init__(self, username):
        self.username = username

    def generate_key(self):
        private_key = x25519.X25519PrivateKey.generate()
        public = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        private_hex = private_bytes.hex()
        public_hex = public_bytes.hex()

        with open("key.txt", "w") as _file:
            _file.write(private_hex)
            _file.close()

        return public_hex

    def connect_to_endpoint(self):
        data = {"username" : self.username, "key" : self.generate_key()}
        response = requests.post("http://127.0.0.1:8000/register", json=data)
        print(response.text)

if __name__ == "__main__":
    client = Client("Aarush")
    client.connect_to_endpoint()
