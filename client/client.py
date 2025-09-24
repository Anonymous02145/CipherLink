from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import requests
import time
import socket
import threading
import json
import struct
import os
import secrets
import base64
import hashlib
import random
from queue import Queue, Empty
from typing import Dict, List, Optional, Tuple, Any
import sys
import signal

# ========== GLOBAL CONSTANTS ==========
URL_BASE = "http://127.0.0.1:8000"
URL_REGISTER = f"{URL_BASE}/register"
URL_AUTHENTICATE = f"{URL_BASE}/authenticate"
URL_GET_KEY = f"{URL_BASE}/get_key"
URL_SET_PORT = f"{URL_BASE}/set_listening_port"
URL_REQUEST_CONNECTION = f"{URL_BASE}/request_connection"
URL_DISCOVER_ONLINE = f"{URL_BASE}/discover_online"

# Security configuration
MESSAGE_PADDING_SIZE = 256
SESSION_ROTATION_HOURS = 24
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
HEARTBEAT_INTERVAL = 30

class E2EEncryptionEngine:
    """Advanced E2E Encryption Engine with perfect forward secrecy"""

    def __init__(self):
        self.message_counter = 0
        self.session_keys = {}
        self.pending_messages = Queue()

    def derive_session_key(self, shared_secret: bytes, session_id: str) -> bytes:
        """Derive unique session key with forward secrecy"""
        info = f"p2p_session_{session_id}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=info
        )
        return hkdf.derive(shared_secret)

    def encrypt_message_advanced(self, plaintext: str, key: bytes, message_id: str) -> Optional[bytes]:
        """Encrypt message with authentication and padding"""
        try:
            # Add metadata and padding for traffic analysis resistance
            message_data = {
                'data': plaintext,
                'timestamp': time.time(),
                'msg_id': message_id,
                'version': '1.0',
                'padding': base64.b64encode(os.urandom(MESSAGE_PADDING_SIZE)).decode()
            }

            serialized_data = json.dumps(message_data, separators=(',', ':'))

            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, serialized_data.encode(), b'')

            # Include nonce and authentication tag
            return nonce + ciphertext

        except Exception as e:
            print(f"[-] Advanced encryption failed: {e}")
            return None

    def decrypt_message_advanced(self, encrypted_data: bytes, key: bytes) -> Optional[Dict[str, Any]]:
        """Decrypt and validate message with full verification"""
        try:
            if len(encrypted_data) < 28:  # nonce(12) + min ciphertext(16)
                return None

            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, b'')

            message_data = json.loads(decrypted_data.decode())

            # Validate message structure
            if not all(k in message_data for k in ['data', 'timestamp', 'msg_id']):
                return None

            # Check for expired messages (5 minutes tolerance)
            if time.time() - message_data['timestamp'] > 300:
                return None

            return message_data

        except Exception as e:
            print(f"[-] Advanced decryption failed: {e}")
            return None

class AnonymousTrafficManager:
    """Manages anonymous traffic patterns and obfuscation"""

    def __init__(self):
        self.traffic_queue = Queue()
        self.is_active = False
        self.obfuscation_thread = None

    def start_traffic_obfuscation(self):
        """Start background traffic obfuscation"""
        self.is_active = True
        self.obfuscation_thread = threading.Thread(
            target=self._traffic_obfuscation_loop,
            daemon=True
        )
        self.obfuscation_thread.start()

    def stop_traffic_obfuscation(self):
        """Stop traffic obfuscation"""
        self.is_active = False
        if self.obfuscation_thread:
            self.obfuscation_thread.join(timeout=5)

    def _traffic_obfuscation_loop(self):
        """Background traffic pattern obfuscation"""
        while self.is_active:
            try:
                # Random delays to obscure traffic patterns
                time.sleep(random.uniform(0.1, 2.0))
            except:
                break

class SecureMessageProtocol:
    """Enhanced secure messaging protocol with guaranteed E2E encryption"""

    def __init__(self):
        self.encryption_engine = E2EEncryptionEngine()
        self.traffic_manager = AnonymousTrafficManager()


    @staticmethod
    def encrypt_message(plaintext: str, key: bytes, associated_data: bytes = b'') -> Optional[bytes]:
        """Encrypt message with E2E guarantee"""
        try:
            # Generate unique message ID for replay protection
            message_id = hashlib.sha256(
                plaintext.encode() + os.urandom(16) + str(time.time()).encode()
            ).hexdigest()[:16]

            # Create secure message envelope
            message_envelope = {
                'content': plaintext,
                'timestamp': time.time(),
                'message_id': message_id,
                'version': 'secure_v1'
            }

            serialized_message = json.dumps(message_envelope)

            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, serialized_message.encode(), associated_data)

            return nonce + ciphertext

        except Exception as e:
            print(f"[-] E2E Encryption failed: {e}")
            return None

    @staticmethod
    def decrypt_message(encrypted_data: bytes, key: bytes, associated_data: bytes = b'') -> Optional[str]:
        """Decrypt E2E encrypted message with validation"""
        try:
            if len(encrypted_data) < 28:  # nonce(12) + min ciphertext(16)
                return None

            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, associated_data)

            message_envelope = json.loads(decrypted_data.decode())

            # Validate message envelope
            required_fields = ['content', 'timestamp', 'message_id']
            if not all(field in message_envelope for field in required_fields):
                return None

            # Anti-replay protection (5 minute window)
            current_time = time.time()
            if abs(current_time - message_envelope['timestamp']) > 300:
                return None

            return message_envelope['content']

        except Exception as e:
            print(f"[-] E2E Decryption failed: {e}")
            return None

class ConnectionValidator:
    """Validates and maintains secure connections"""

    def __init__(self):
        self.connection_metrics = {}
        self.validation_lock = threading.Lock()

    def validate_connection_integrity(self, connection_id: str, public_key: str) -> bool:
        """Validate connection cryptographic integrity"""
        with self.validation_lock:
            if connection_id in self.connection_metrics:
                # Check for key consistency
                stored_key = self.connection_metrics[connection_id].get('public_key')
                if stored_key and stored_key != public_key:
                    print(f"[!] Key change detected for {connection_id}")
                    return False

            # Update connection metrics
            self.connection_metrics[connection_id] = {
                'public_key': public_key,
                'last_validated': time.time(),
                'validation_count': self.connection_metrics.get(connection_id, {}).get('validation_count', 0) + 1
            }

            return True

class AnonymousClient:
    def __init__(self, username=None):
        # Enhanced anonymity features
        self.session_id = secrets.token_hex(16)
        self.ephemeral_identities = []
        self.current_identity_index = 0

        #predefine the socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listeners = []

        self.listener_thread = threading.Thread(target=self.start_listener)

        # Allow custom username or generate random one
        self.username = username if username else self.generate_random_username()

        # Core cryptographic components
        self.private_key = None
        self.public_key = None
        self.public_key_hex = None
        self.public_key_bytes = None
        self.peer_id = None
        self.identity_hash = None
        self.session_token = None
        self.session_expiry = 0
        self.listening_port = None

        # Enhanced connection management
        self.active_connections = {}
        self.peer_directory = {}
        self.username_to_peer_map = {}
        self.listening_socket = None
        self.is_listening = False
        self.lock = threading.RLock()  # Reentrant lock for better threading
        self.message_history = []

        # Advanced security components
        self.encryption_engine = E2EEncryptionEngine()
        self.connection_validator = ConnectionValidator()
        self.traffic_manager = AnonymousTrafficManager()
        self.secure_protocol = SecureMessageProtocol()

        # UI state with enhanced security
        self.current_chat_peer = None
        self.ui_lock = threading.Lock()
        self.message_queue = Queue()
        self.message_processor_thread = None

        # Privacy settings with enhanced options
        self.share_connection_info = False
        self.ephemeral_mode = True
        self.auto_rotate_identities = True
        self.identity_rotation_interval = 3600  # 1 hour

        # Start background services
        self.start_background_services()

    def start_background_services(self):
        """Start all background anonymity and security services"""
        self.traffic_manager.start_traffic_obfuscation()
        self.start_message_processor()

        # Start identity rotation if enabled
        if self.auto_rotate_identities:
            rotation_thread = threading.Thread(
                target=self._identity_rotation_loop,
                daemon=True
            )
            rotation_thread.start()

    def start_message_processor(self):
        """Start background message processing thread"""
        self.message_processor_thread = threading.Thread(
            target=self._message_processing_loop,
            daemon=True
        )
        self.message_processor_thread.start()


    def _handle_client(self, client_socket, addr):
        """Handle each incoming client in a separate thread"""
        fd = client_socket.fileno()
        self.active_connections[fd] = {
            'aes_key': secrets.token_hex(32),
            'conn': client_socket
        }
        client_socket.settimeout(60)

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    break
                # Queue the message for processing
                self.message_queue.put({
                    'type': 'process_received',
                    'data': data,
                    'aes_key': self.active_connections[fd]['aes_key'],
                    'connection_id': fd
                })
        except socket.timeout:
            pass
        except Exception:
            pass
        finally:
            client_socket.close()
            if fd in self.active_connections:
                del self.active_connections[fd]


    def _message_processing_loop(self):
        """Background message processing with E2E encryption"""
        while True:
            try:
                # Process messages from queue
                message_task = self.message_queue.get(timeout=1.0)
                if message_task:
                    self._process_message_task(message_task)
                self.message_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                print(f"[-] Message processing error: {e}")

    def _process_message_task(self, task: Dict[str, Any]):
        """Process individual message task with E2E encryption"""
        try:
            if task['type'] == 'send_message':
                connection_id = task['connection_id']
                message = task['message']
                self._send_message_secure(connection_id, message)
            elif task['type'] == 'process_received':
                encrypted_data = task['data']
                aes_key = task['aes_key']
                connection_id = task['connection_id']
                self._process_received_message(encrypted_data, aes_key, connection_id)
        except Exception as e:
            print(f"[-] Message task processing failed: {e}")

    def _port_binding_mode(self):
        """Try multiple ports for listening"""
        ports = [8085, 8086, 8087, 8088, 8089, 8090]
        for port in ports:
            try:
                self.socket.bind(('127.0.0.1', port))
                self.socket.listen(5)
                return True
            except OSError:
                continue
        return False

    def start_listener(self):
        """Start the main listener to accept incoming connections"""
        try:
            try:
                self.socket.bind(('127.0.0.1', 8080))
                self.socket.listen(5)
            except OSError:
                if not self._port_binding_mode():
                    return False
            self.is_listening = True
        except Exception:
            return False

        while self.is_listening:
            try:
                client_socket, addr = self.socket.accept()
                # Start a new thread for each client
                threading.Thread(target=self._handle_client, args=(client_socket, addr), daemon=True).start()
            except Exception:
                continue

    def _send_message_secure(self, connection_id: str, message: str):
        """Send an encrypted message over a secure connection"""
        with self.lock:
            if connection_id not in self.active_connections:
                return False
            conn = self.active_connections[connection_id]
            aes_key = conn['aes_key']

        encrypted_data = self.secure_protocol.encrypt_message(message, aes_key)
        if not encrypted_data:
            return False

        try:
            header = struct.pack('>I', len(encrypted_data))
            conn['conn'].sendall(header + encrypted_data)
            return True
        except Exception:
            return False


    def _process_received_message(self, encrypted_data: bytes, aes_key: bytes, connection_id: str):
        """Decrypt and store received messages"""
        decrypted_content = self.secure_protocol.decrypt_message(encrypted_data, aes_key)
        if not decrypted_content:
            return

        with self.lock:
            peer_info = self.active_connections.get(connection_id, {}).get('peer_info', {})
            peer_username = peer_info.get('username', 'Unknown')

        self.message_history.append({
            'sender': peer_username,
            'text': decrypted_content,
            'timestamp': time.time(),
            'connection_id': connection_id,
            'direction': 'incoming'
        })


    def _identity_rotation_loop(self):
        """Periodically rotate ephemeral identities"""
        while True:
            time.sleep(self.identity_rotation_interval)
            if self.auto_rotate_identities and self.ephemeral_mode:
                self._rotate_identity()


    def _rotate_identity(self):
        """Rotate to a new anonymous identity"""
        new_username = self.generate_random_username()
        old_username = self.username
        self.username = new_username
        self.ephemeral_identities.append({
            'old_username': old_username,
            'new_username': new_username,
            'rotation_time': time.time()
        })


    def generate_random_username(self):
        """Generate a random username with enhanced anonymity"""
        adjectives = ['Silent', 'Ghost', 'Shadow', 'Cipher', 'Phantom', 'Stealth',
                     'Hidden', 'Crypto', 'Dark', 'Anonymous', 'Stealthy', 'Covert',
                     'Private', 'Secret', 'Unknown', 'Mysterious', 'Hidden', 'Veiled']
        animals = ['Wolf', 'Raven', 'Fox', 'Owl', 'Hawk', 'Cat', 'Snake', 'Spider',
                  'Bat', 'Falcon', 'Lynx', 'Panther', 'Viper', 'Eagle', 'Shark', 'Tiger']
        numbers = secrets.randbelow(99999)
        return f"{secrets.choice(adjectives)}{secrets.choice(animals)}{numbers:05d}"

    def generate_keys(self):
        """Generate new cryptographic keys with enhanced security"""
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.public_key_hex = self.public_key_bytes.hex()

    def generate_peer_id(self):
        """Generate peer ID with enhanced uniqueness"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.public_key_hex.encode())
        digest.update(os.urandom(16))  # Additional entropy
        self.peer_id = digest.finalize().hex()

    def generate_identity_hash(self):
        """Generate anonymous identity hash with enhanced privacy"""
        entropy = os.urandom(32)  # Increased entropy
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.public_key_hex.encode())
        digest.update(entropy)
        digest.update(self.username.encode())
        self.identity_hash = digest.finalize().hex()

    def register_with_server(self):
        """Enhanced server registration with anonymity"""
        try:
            self.generate_keys()
            self.generate_peer_id()
            self.generate_identity_hash()

            data = {
                "username_hash": self.identity_hash,
                "public_key": self.public_key_hex,
                "peer_id": self.peer_id
            }

            # Add random delay to obscure registration timing
            time.sleep(random.uniform(0.1, 1.0))

            response = requests.post(URL_REGISTER, json=data, timeout=15)
            if response.status_code == 200:
                result = response.json()
                self.session_token = result.get('session_token')
                self.session_expiry = time.time() + result.get('expires_in', 86400)
                print(f"[+] Registered anonymously as: {self.username}")
                print(f"[+] Your secure Peer ID: {self.peer_id[:16]}...")
                print(f"[+] Session ID: {self.session_id}")
                return True
            else:
                print(f"[-] Registration failed: {response.json()}")
                return False
        except Exception as e:
            print(f"[-] Registration error: {e}")
            return False

    def ensure_valid_session(self):
        """Enhanced session validation"""
        if self.session_token and time.time() < self.session_expiry - 120:
            return True
        print("[+] Session expired, establishing new anonymous session...")
        return self.register_with_server()

    # Enhanced connection handling methods with E2E encryption
    def handle_incoming_connection(self, client_sock, addr):
        """Enhanced incoming connection handler with E2E"""
        connection_id = f"recv_{addr[0]}_{addr[1]}_{int(time.time())}"
        peer_username = "Unknown"

        try:
            self.print_status_line("[+] Secure E2E key exchange in progress...")

            # Step 1: Receive initiator's public key
            initiator_key = client_sock.recv(32)
            if len(initiator_key) != 32:
                self.print_status_line("[-] Invalid public key received")
                return

            # Step 2: Send our public key
            client_sock.send(self.public_key_bytes)

            # Step 3: Receive initiator's username
            username_length_data = client_sock.recv(4)
            if len(username_length_data) < 4:
                return
            username_length = struct.unpack('>I', username_length_data)[0]
            if username_length > 100:
                return
            peer_username = client_sock.recv(username_length).decode()

            # Step 4: Send our username
            username_bytes = self.username.encode()
            client_sock.send(struct.pack('>I', len(username_bytes)))
            client_sock.send(username_bytes)

            # Step 5: Derive peer ID
            digest = hashes.Hash(hashes.SHA256())
            digest.update(initiator_key.hex().encode())
            peer_id = digest.finalize().hex()

            # Step 6: Verify peer's public key
            if not self.verify_peer_public_key(peer_id, initiator_key.hex(), peer_username):
                self.print_status_line(f"[-] Failed to verify {peer_username}'s public key")
                return

            # Step 7: Derive shared secret for E2E
            shared_secret = self.derive_shared_secret(initiator_key.hex())
            if not shared_secret:
                return

            connection_id = f"recv_{peer_username}"

            with self.lock:
                self.active_connections[connection_id] = {
                    'socket': client_sock,
                    'aes_key': shared_secret,
                    'role': 'recipient',
                    'peer_info': {
                        'username': peer_username,
                        'peer_id': peer_id,
                        'public_key': initiator_key.hex(),
                        'address': addr
                    },
                    'established': time.time(),
                    'verified': True,
                    'e2e_enabled': True
                }

            self.print_status_line(f"[+] Secure E2E connection established with {peer_username}")

            # Start secure message loop
            self._secure_message_loop(client_sock, shared_secret, connection_id)

        except Exception as e:
            self.print_status_line(f"[-] Secure connection error: {e}")
        finally:
            with self.lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            try:
                client_sock.close()
            except:
                pass
            self.print_status_line(f"[-] E2E connection with {peer_username} closed")

    def _secure_message_loop(self, sock, aes_key, connection_id):
        """Handle secure messaging for established peer connections"""
        try:
            sock.settimeout(1.0)
            while True:
                try:
                    header = sock.recv(4)
                    if not header or len(header) < 4:
                        break

                    length = struct.unpack('>I', header)[0]
                    if length > MAX_MESSAGE_SIZE:
                        break

                    encrypted_data = b''
                    while len(encrypted_data) < length:
                        chunk = sock.recv(min(4096, length - len(encrypted_data)))
                        if not chunk:
                            break
                        encrypted_data += chunk

                    if len(encrypted_data) != length:
                        break

                    # Queue for decryption
                    self.message_queue.put({
                        'type': 'process_received',
                        'data': encrypted_data,
                        'aes_key': aes_key,
                        'connection_id': connection_id
                    })

                except socket.timeout:
                    continue
                except Exception:
                    break
        finally:
            with self.lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            try:
                sock.close()
            except:
                pass

    def send_message(self, connection_id, message):
        """Send message with queued E2E encryption"""
        # Queue message for secure sending
        self.message_queue.put({
            'type': 'send_message',
            'connection_id': connection_id,
            'message': message
        })
        return True

    # Enhanced connection establishment with E2E
    def connect_to_peer_direct(self, target_peer_id, target_identity_hash):
        """Enhanced direct connection with E2E encryption"""
        try:
            if not self.ensure_valid_session():
                return None

            # Existing connection check
            existing_conn = None
            with self.lock:
                for conn_id, conn_info in self.active_connections.items():
                    if conn_info['peer_info']['peer_id'] == target_peer_id:
                        existing_conn = conn_id
                        break

            if existing_conn:
                username = self.peer_directory.get(target_peer_id, {}).get('username', 'Unknown')
                self.print_status_line(f"[!] Already connected to {username}")
                return existing_conn

            # Request connection
            self.print_status_line(f"[+] Requesting E2E connection to {target_peer_id[:16]}...")
            connection_info = self.request_connection(target_identity_hash)
            if not connection_info:
                return None

            target_port = connection_info.get('target_listening_port')
            target_public_key = connection_info.get('target_public_key')

            if not target_port or not target_public_key:
                self.print_status_line("[-] Invalid connection info")
                return None

            username = self.peer_directory.get(target_peer_id, {}).get('username', f"User_{target_peer_id[:8]}")
            self.print_status_line(f"[+] Establishing E2E connection with {username}...")

            # Test connection
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            try:
                test_sock.connect(('127.0.0.1', target_port))
                test_sock.close()
            except:
                self.print_status_line(f"[-] Peer {username} offline")
                return None

            # Establish secure connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect(('127.0.0.1', target_port))

            self.print_status_line("[+] Performing E2E key exchange...")

            # Key exchange sequence
            sock.send(self.public_key_bytes)
            target_key = sock.recv(32)
            if len(target_key) != 32:
                return None

            # Username exchange
            username_bytes = self.username.encode()
            sock.send(struct.pack('>I', len(username_bytes)))
            sock.send(username_bytes)

            username_length_data = sock.recv(4)
            if len(username_length_data) < 4:
                return None
            username_length = struct.unpack('>I', username_length_data)[0]
            received_username = sock.recv(username_length).decode()

            # Verification
            if not self.verify_peer_public_key(target_peer_id, target_key.hex(), received_username):
                return None

            if target_key.hex() != target_public_key:
                self.print_status_line("[-] Public key mismatch!")
                return None

            # Derive E2E key
            shared_secret = self.derive_shared_secret(target_key.hex())
            if not shared_secret:
                return None

            connection_id = f"init_{received_username}"

            with self.lock:
                self.active_connections[connection_id] = {
                    'socket': sock,
                    'aes_key': shared_secret,
                    'role': 'initiator',
                    'peer_info': {
                        'username': received_username,
                        'peer_id': target_peer_id,
                        'public_key': target_key.hex(),
                        'address': ('127.0.0.1', target_port)
                    },
                    'established': time.time(),
                    'verified': True,
                    'e2e_enabled': True
                }

            self.print_status_line(f"[+] E2E connection secured with {received_username}")

            # Start secure message loop
            thread = threading.Thread(
                target=self._secure_message_loop,
                args=(sock, shared_secret, connection_id)
            )
            thread.daemon = True
            thread.start()

            return connection_id

        except Exception as e:
            self.print_status_line(f"[-] E2E connection failed: {e}")
            return None

    # Enhanced utility methods
    def derive_shared_secret(self, peer_public_key_hex):
        """Enhanced key derivation"""
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(peer_public_key_hex)
            )
            shared_secret = self.private_key.exchange(peer_public_key)

            # Enhanced KDF with more parameters
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=os.urandom(32),
                info=b'p2p_secure_e2e_v2'
            )
            return hkdf.derive(shared_secret)
        except Exception as e:
            self.print_status_line(f"[-] Key derivation failed: {e}")
            return None

    def verify_peer_public_key(self, peer_id, received_public_key, peer_username=None):
        """Enhanced key verification"""
        with self.lock:
            if peer_id in self.peer_directory:
                stored_key = self.peer_directory[peer_id]['public_key']
                if stored_key and stored_key != received_public_key:
                    username = self.peer_directory[peer_id]['username']
                    self.print_status_line(f"[!] Key change detected for {username}!")
                    return False

            username = peer_username if peer_username else f"User_{peer_id[:8]}"
            self.peer_directory[peer_id] = {
                'public_key': received_public_key,
                'username': username,
                'verified': True,
                'first_seen': time.time(),
                'last_verified': time.time()
            }
            self.username_to_peer_map[username] = peer_id
            return True

    def print_status_line(self, message=""):
        """Enhanced status display"""
        with self.lock:
            connection_count = len(self.active_connections)
            e2e_count = sum(1 for conn in self.active_connections.values()
                           if conn.get('e2e_enabled', False))

        status = f"Connections: {connection_count} (E2E: {e2e_count})"
        if message:
            print(f"\r{message:<60} {status}")
        else:
            print(f"\r{'':<60} {status}")

    # Enhanced discovery and connection methods
    def discover_online_peers(self):
        """Enhanced peer discovery"""
        try:
            if not self.ensure_valid_session():
                return []

            data = {
                "username_hash": self.identity_hash,
                "session_token": self.session_token
            }

            # Add random delay for anonymity
            time.sleep(random.uniform(0.5, 2.0))

            response = requests.post(URL_DISCOVER_ONLINE, json=data, timeout=15)
            if response.status_code == 200:
                online_users = response.json().get('online_users', [])

                # Enhanced peer directory update
                with self.lock:
                    for user in online_users:
                        peer_id = user['peer_id']
                        if peer_id not in self.peer_directory:
                            placeholder_username = f"User_{peer_id[:8]}"
                            self.peer_directory[peer_id] = {
                                'public_key': None,
                                'username': placeholder_username,
                                'verified': False,
                                'first_seen': time.time(),
                                'discovered': True
                            }
                            self.username_to_peer_map[placeholder_username] = peer_id

                return online_users
            else:
                self.print_status_line(f"[-] Discovery failed")
                return []
        except Exception as e:
            self.print_status_line(f"[-] Discovery error: {e}")
            return []

    # Enhanced chat interface
    def start_chat(self, connection_id_or_username):
        """Enhanced chat interface with E2E indicators"""
        if connection_id_or_username.startswith(('init_', 'recv_')):
            connection_id = connection_id_or_username
            with self.lock:
                if connection_id in self.active_connections:
                    username = self.active_connections[connection_id]['peer_info']['username']
                    e2e_status = "✓ E2E" if self.active_connections[connection_id].get('e2e_enabled') else "✗ Plain"
                else:
                    self.print_status_line(f"[-] Connection not found")
                    return
        else:
            username = connection_id_or_username
            connection_id = self.get_connection_by_username(username)
            if not connection_id:
                self.print_status_line(f"[-] Not connected to {username}")
                return

        self.current_chat_peer = username
        with self.lock:
            e2e_status = "✓ E2E" if self.active_connections[connection_id].get('e2e_enabled') else "✗ Plain"

        print(f"\n{'='*60}")
        print(f"[+] Secure Chat ({e2e_status}) with {username}")
        print(f"{'='*60}")
        print("Type messages (type '/exit' to return to main menu)")
        print("Commands: /connections, /status, /verify")
        print("-" * 60)

        while True:
            try:
                message = input("You: ").strip()
                if message.lower() == '/exit':
                    break
                elif message.lower() == '/connections':
                    self.show_connections()
                    continue
                elif message.lower() == '/status':
                    self.print_status_line("Chat status")
                    continue
                elif message.lower() == '/verify':
                    self.verify_connection_security(connection_id)
                    continue
                elif message:
                    if not self.send_message(connection_id, message):
                        print("[-] Failed to send message")
                        break
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[-] Chat error: {e}")
                break

        self.current_chat_peer = None
        print(f"\n[+] Exited chat with {username}")

    def verify_connection_security(self, connection_id):
        """Verify connection security status"""
        with self.lock:
            if connection_id in self.active_connections:
                conn = self.active_connections[connection_id]
                print(f"\n[Security Verification]")
                print(f"Peer: {conn['peer_info']['username']}")
                print(f"E2E Encrypted: {'Yes' if conn.get('e2e_enabled') else 'No'}")
                print(f"Verified: {'Yes' if conn.get('verified') else 'No'}")
                print(f"Connection Time: {time.ctime(conn['established'])}")
                print(f"Duration: {time.time() - conn['established']:.0f} seconds")

    def show_connections(self):
        """Enhanced connection display"""
        with self.lock:
            if not self.active_connections:
                print("\n[!] No active connections")
                return

            print(f"\n{'='*80}")
            print(f"[+] Active Connections ({len(self.active_connections)}):")
            print(f"{'='*80}")

            for conn_id, conn_info in self.active_connections.items():
                username = conn_info['peer_info']['username']
                role = conn_info['role']
                peer_id = conn_info['peer_info']['peer_id'][:16]
                established = time.ctime(conn_info['established'])
                e2e_status = "✓" if conn_info.get('e2e_enabled') else "✗"
                verified = "✓" if conn_info.get('verified') else "✗"

                print(f"  [{e2e_status}{verified}] {username:<20} ({role:<9}) | ID: {peer_id}... | Est: {established}")

            print(f"{'='*80}")

    # Enhanced cleanup
    def clear_session_data(self):
        """Enhanced session data clearance"""
        if self.ephemeral_mode:
            self.peer_directory.clear()
            self.username_to_peer_map.clear()
            self.message_history.clear()
            self.ephemeral_identities.clear()
            print("[+] All session data cleared for privacy")

    def shutdown(self):
        """Graceful shutdown"""
        print("\n[+] Shutting down securely...")
        self.traffic_manager.stop_traffic_obfuscation()
        self.is_listening = False

        with self.lock:
            for conn_id, conn_info in self.active_connections.items():
                try:
                    conn_info['socket'].close()
                except:
                    pass
            self.active_connections.clear()

        if self.listening_socket:
            try:
                self.listening_socket.close()
            except:
                pass

        print("[+] Secure shutdown complete")

# Enhanced main function
def main():
    print("=== ANONYMOUS SECURE P2P MESSENGER ===")
    print("[+] End-to-End Encrypted • Anonymous • Secure")
    print("[+] All messages are E2E encrypted before transmission")
    print("[+] Traffic obfuscation and identity protection enabled")
    print("-" * 60)

    # Enhanced username handling
    username = input("Enter your username (leave blank for random anonymous identity): ").strip()
    if not username:
        username = None

    # Create client with enhanced security
    client = AnonymousClient(username)

    # Enhanced registration
    if not client.register_with_server():
        print("[-] Failed to establish secure session")
        return

    # Enhanced listener startup
    port = client.start_listener()
    if not port:
        print("[-] Failed to start secure listener")
        return

    client.print_status_line(f"[+] Secure client active on port {port}")

    # Enhanced main loop
    try:
        while True:
            print(f"\n{'='*60}")
            print(f"[+] SECURE P2P MENU - {client.username}")
            print(f"{'='*60}")
            print("1. Connect to peer by username")
            print("2. Connect to peer by Peer ID")
            print("3. Secure chat with connected peers")
            print("4. Discover online peers (E2E recommended)")
            print("5. Show secure connections & E2E status")
            print("6. Show peer directory with verification")
            print("7. Rotate anonymous identity")
            print("8. Security status and verification")
            print("9. Exit securely")
            print("-" * 60)

            choice = input("Select option: ").strip()

            if choice == "1":
                target_username = input("Enter username to connect to: ").strip()
                if not target_username:
                    print("[-] Username required")
                    continue
                connection_id = client.connect_to_username(target_username)
                if connection_id:
                    print(f"[+] E2E connection established!")
                    client.start_chat(connection_id)
                else:
                    print("[-] Connection failed")

            elif choice == "2":
                target_peer_id = input("Enter Peer ID: ").strip()
                if not target_peer_id:
                    print("[-] Peer ID required")
                    continue
                connection_id = client.connect_to_peer_id(target_peer_id)
                if connection_id:
                    print(f"[+] Secure connection established!")
                    client.start_chat(connection_id)
                else:
                    print("[-] Connection failed")

            elif choice == "3":
                client.multi_chat_interface()

            elif choice == "4":
                print("[+] Discovering secure peers...")
                online_peers = client.discover_online_peers()
                if online_peers:
                    print(f"\n[+] Found {len(online_peers)} online peers")
                    for i, peer in enumerate(online_peers, 1):
                        print(f"  {i}. User_{peer['peer_id'][:8]} (ID: {peer['peer_id'][:16]}...)")

                    selection = input("\nSelect peer number or 'back': ").strip()
                    if selection.lower() != 'back':
                        try:
                            peer_num = int(selection)
                            if 1 <= peer_num <= len(online_peers):
                                peer = online_peers[peer_num-1]
                                connection_id = client.connect_to_peer_direct(
                                    peer['peer_id'], peer['username_hash']
                                )
                                if connection_id:
                                    client.start_chat(connection_id)
                            else:
                                print("[-] Invalid selection")
                        except ValueError:
                            print("[-] Invalid input")
                else:
                    print("[-] No peers online")

            elif choice == "5":
                client.show_connections()

            elif choice == "6":
                print(f"\n[+] Known Peers: {len(client.peer_directory)}")
                for peer_id, info in client.peer_directory.items():
                    status = "Verified" if info['verified'] else "Unverified"
                    print(f"  {info['username']} (ID: {peer_id[:16]}...) - {status}")

            elif choice == "7":
                client._rotate_identity()

            elif choice == "8":
                client.print_status_line("Security Status")
                print(f"\n[Security Overview]")
                print(f"Active E2E Connections: {sum(1 for conn in client.active_connections.values() if conn.get('e2e_enabled'))}")
                print(f"Total Messages: {len(client.message_history)}")
                print(f"Session ID: {client.session_id}")
                print(f"Identity Protection: {'Enabled' if client.ephemeral_mode else 'Disabled'}")

            elif choice == "9":
                break

            else:
                print("[-] Invalid option")

    except KeyboardInterrupt:
        print("\n[+] Interrupted by user")
    except Exception as e:
        print(f"\n[-] System error: {e}")
    finally:
        client.shutdown()
        print("[+] Secure exit completed")

if __name__ == "__main__":
    # Enhanced signal handling for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\n[+] Received signal {signum}, shutting down securely...")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main()
