from .include import *
from .encryption import *
from .file_transfer import *
from .protocols import *
from .validation import *
from .traffic_manager import *
from .logger import *
from .chat_interface import *
from .tor_route import initialize_tor, TorSocketWrapper, shutdown_tor

class AnonymousClient:
    def __init__(self, username=None):
            self.session_id = secrets.token_hex(16)
            self.chat_active = False
            self.ephemeral_identities = []
            self.current_identity_index = 0

            self.chunk_size = 8192
            self.transfers = {}

            self.username = username if username else self.generate_random_username()

            # CRITICAL: Generate keys IMMEDIATELY before anything else
            self.private_key = None
            self.public_key = None
            self.public_key_hex = None
            self.to_send = None
            self.public_key_bytes = None

            # Generate unique keys for this instance RIGHT NOW
            if not self.generate_keys():
                raise Exception("Failed to generate cryptographic keys")

            print(f"[DEBUG] Generated unique keys for {self.username}: {self.public_key_hex[:16]}...")

            self.peer_id = None
            self.identity_hash = None
            self.session_token = None
            self.session_expiry = 0
            self.listening_port = None

            self.active_connections = {}
            self.peer_directory = {}
            self.username_to_peer_map = {}
            self.listening_socket = None
            self.is_listening = False
            self.client_socket = None
            self.lock = threading.RLock()
            self.message_history = []

            self.encryption_engine = E2EEncryptionEngine()
            self.connection_validator = ConnectionValidator()
            self.traffic_manager = AnonymousTrafficManager()
            self.secure_protocol = SecureMessageProtocol()

            self.current_chat_peer = None
            self.ui_lock = threading.Lock()
            self.message_queue = Queue()
            self.message_processor_thread = None

            self.share_connection_info = False
            self.ephemeral_mode = True
            self.auto_rotate_identities = True
            self.identity_rotation_interval = 3600

            self.unique_client_id = str(uuid.uuid4())
            self.anonymized_metadata = {}


            print("[+] Initializing Tor network...")
            self.tor_instance = initialize_tor()
            self.tor_wrapper = TorSocketWrapper(self.tor_instance)
            self.onion_address = None
            print("[+] Tor initialization complete")

            self.start_background_services()
            self.chat_interface = BidirectionalChatInterface(self)

    def discover_online_peers(self):
        try:
            if not self.ensure_valid_session():
                    return []

            data = {
                "username_hash": self.identity_hash,
                "session_token": self.session_token,
            }

            time.sleep(random.uniform(0.5, 2.0))

            response = requests.post(URL_DISCOVER_ONLINE, json=data, timeout=15)
            if response.status_code == 200:
                online_users = response.json().get("online_users", [])

                print(f"[+] Found {len(online_users)} online peers:")
                for i, user in enumerate(online_users, 1):
                    peer_id = user["peer_id"]
                    username_hash = user.get("username_hash", "Unknown")
                    print(f"  {i}. User_{peer_id[:8]} (ID: {peer_id[:16]}...)")

                with self.lock:
                    for user in online_users:
                            peer_id = user["peer_id"]
                            if peer_id not in self.peer_directory:
                                placeholder_username = f"User_{peer_id[:8]}"
                                self.peer_directory[peer_id] = {
                                    "public_key": user.get("public_key"),
                                    "username": placeholder_username,
                                    "verified": False,
                                    "first_seen": time.time(),
                                    "discovered": True,
                                    "username_hash": user.get("username_hash")
                                }
                                self.username_to_peer_map[placeholder_username] = peer_id

                return online_users
            else:
                print(f"[-] Discover request failed: {response.status_code}")
                return []
        except Exception as e:
            print(f"[-] Discover online peers error: {e}")
            return []

    def _receive_chunk(self, connection_id: str) -> Optional[bytes]:
        try:
            with self.lock:
                if connection_id not in self.active_connections:
                    return None
                conn = self.active_connections[connection_id]
                sock = conn["socket"]
                aes_key = conn["aes_key"]

            header = sock.recv(4)
            if len(header) < 4:
                return None

            chunk_length = struct.unpack(">I", header)[0]
            if chunk_length > MAX_MESSAGE_SIZE:
                return None

            encrypted_chunk = b""
            while len(encrypted_chunk) < chunk_length:
                chunk = sock.recv(min(4096, chunk_length - len(encrypted_chunk)))
                if not chunk:
                    break
                encrypted_chunk += chunk
            if len(encrypted_chunk) != chunk_length:
                return None

            ftp = FileTransferProtocol()
            chunk_envelope = ftp.decrypt_file_chunk(encrypted_chunk, aes_key)
            if not chunk_envelope:
                return None

            return base64.b64decode(chunk_envelope["data"])

        except Exception as e:
            print(f"[-] Failed to receive chunk: {e}")
            return None

    def send_file(self, connection_id: str, file_path: str):
        try:
            with self.lock:
                if connection_id not in self.active_connections:
                    return False
                conn = self.active_connections[connection_id]
                aes_key = conn["aes_key"]

            ftp = FileTransferProtocol()
            file_info = ftp.prepare_file_transfer(file_path)

            if not file_info:
                return False

            file_info_message = {"type": "file_transfer_start", "file_info": file_info}

            if not self._send_message_secure(
                connection_id, json.dumps(file_info_message)
            ):
                return False

            for chunk_index in range(file_info["total_chunks"]):
                encrypted_chunk = ftp.encrypt_file_chunk(
                    file_info["transfer_id"], chunk_index, aes_key
                )
                if not encrypted_chunk:
                    return False

                header = struct.pack(">I", len(encrypted_chunk))
                conn["socket"].sendall(header + encrypted_chunk)

                time.sleep(0.01)

            return True

        except Exception as e:
            print(f"[-] File transfer failed: {e}")
            return False

    def _handle_file_transfer(self, file_info: Dict[str, Any], connection_id: str):
        try:
            print(
                f"[+] Incoming file: {file_info['file_name']} ({file_info['file_size']} bytes)"
            )

            os.makedirs("downloads", exist_ok=True)
            file_path = os.path.join("downloads", file_info["file_name"])

            with open(file_path, "wb") as f:
                for chunk_index in range(file_info["total_chunks"]):
                    chunk_data = self._receive_chunk(connection_id)
                    if not chunk_data:
                        print(f"[-] Failed to receive chunk {chunk_index}")
                        return False

                    f.write(chunk_data)
                    print(
                        f"[+] Received chunk {chunk_index + 1}/{file_info['total_chunks']}"
                    )

            print(f"[+] File received successfully: {file_path}")
            return True

        except Exception as e:
            print(f"[-] File reception failed: {e}")
            return False

    def _handle_file_transfer_threaded(
        self, file_info: Dict[str, Any], connection_id: str, peer_username: str
    ):
        try:
            print(f"\n[+] Starting file transfer from {peer_username}...")
            success = self._handle_file_transfer(file_info, connection_id)
            if success:
                print(f"[+] File transfer from {peer_username} completed successfully!")
            else:
                print(f"[-] File transfer from {peer_username} failed!")
        except Exception as e:
            print(f"[-] File transfer thread error: {e}")

    def generate_random_username(self):
        prefixes = [
            "Ghost",
            "Shadow",
            "Cipher",
            "Phantom",
            "Stealth",
            "Hidden",
            "Crypto",
            "Dark",
            "Anonymous",
            "Secure",
            "Private",
            "Secret",
            "Unknown",
            "Mysterious",
            "Veiled",
            "Silent",
            "Covert",
            "Ninja",
            "Void",
            "Anon",
        ]
        suffixes = [
            "Wolf",
            "Raven",
            "Fox",
            "Owl",
            "Hawk",
            "Cat",
            "Snake",
            "Spider",
            "Bat",
            "Falcon",
            "Lynx",
            "Panther",
            "Viper",
            "Eagle",
            "Shark",
            "Tiger",
            "Bear",
            "Dragon",
            "Cobra",
        ]
        numbers = secrets.randbelow(99999)
        return f"{secrets.choice(prefixes)}{secrets.choice(suffixes)}{numbers:05d}"

    def generate_keys(self):
        try:
            self.private_key = x25519.X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            self.public_key_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self.to_send = self.public_key_bytes
            self.public_key_hex = self.public_key_bytes.hex()
            return True
        except Exception:
            return False

    def generate_peer_id(self):
        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self.public_key_hex.encode())
            digest.update(os.urandom(16))
            digest.update(str(time.time()).encode())
            self.peer_id = digest.finalize().hex()
            print(f"Generated peer ID: {self.peer_id}")
            return True
        except Exception:
            return False

    def generate_identity_hash(self):
        try:
            entropy = os.urandom(32)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(self.public_key_hex.encode())
            digest.update(entropy)
            digest.update(self.username.encode())
            digest.update(self.session_id.encode())
            self.identity_hash = digest.finalize().hex()
            return True
        except Exception:
            return False

    def anonymize_metadata(self, metadata: dict) -> dict:
        anonymized = {}
        for key, value in metadata.items():
            if key in ["ip_address", "location"]:
                anonymized[key] = "REDACTED"
            else:
                anonymized[key] = value
        return anonymized

    def register_with_server(self):
        try:
            # Keys should already be generated in __init__, only generate if missing
            if not self.public_key_hex or not self.private_key:
                if not self.generate_keys():
                    Logger.log_event("ERROR", "Key generation failed during register")
                    return False

            if not self.generate_peer_id():
                Logger.log_event("ERROR", "Peer ID generation failed during register")
                return False
            if not self.generate_identity_hash():
                Logger.log_event("ERROR", "Identity hash generation failed during register")
                return False

            payload = {
                "username_hash": self.identity_hash,
                "public_key": self.public_key_hex,
                "peer_id": self.peer_id,
                "client_id": self.unique_client_id,
                "onion_address": self.onion_address
            }

            payload = self.anonymize_metadata(payload)

            attempts = 3
            backoff = 0.5
            for attempt in range(1, attempts + 1):
                try:
                    time.sleep(random.uniform(0.05, 0.2) + backoff * (attempt - 1))
                    resp = requests.post(URL_REGISTER, json=payload, timeout=10)
                    if resp.status_code != 200:
                        Logger.log_event("WARN", f"Register attempt {attempt} failed: {resp.status_code}")
                        continue

                    try:
                        j = resp.json()
                    except Exception:
                        Logger.log_event("ERROR", "Register response not JSON")
                        continue

                    token = j.get("session_token")
                    expires = j.get("expires_in", 86400)
                    if not token:
                        Logger.log_event("ERROR", "No session token in register response")
                        continue

                    self.session_token = token
                    self.session_expiry = time.time() + int(expires)
                    Logger.log_event("INFO", "Registered with server successfully")
                    print(f"[DEBUG] Registered with public key: {self.public_key_hex[:16]}...")
                    return True

                except requests.Timeout:
                    Logger.log_event("WARN", f"Register attempt {attempt} timed out")
                    time.sleep(backoff * attempt)
                    continue
                except Exception as e:
                    Logger.log_event("ERROR", f"Register attempt {attempt} error: {e}")
                    time.sleep(backoff * attempt)
                    continue

            return False
        except Exception as e:
            Logger.log_event("ERROR", f"Unexpected register failure: {e}")
            return False

    def ensure_valid_session(self):
        try:
            if self.session_token and time.time() < self.session_expiry - 120:
                return True
            return self.register_with_server()
        except Exception:
            return False

    def start_background_services(self):
        try:
            self.traffic_manager.start_traffic_obfuscation()
            self.start_message_processor()

            if self.auto_rotate_identities:
                rotation_thread = threading.Thread(
                    target=self._identity_rotation_loop, daemon=True
                )
                rotation_thread.start()
        except Exception:
            pass

    def start_message_processor(self):
        try:
            self.message_processor_thread = threading.Thread(
                target=self._message_processing_loop, daemon=True
            )
            self.message_processor_thread.start()
        except Exception:
            pass

    def _message_processing_loop(self):
        while True:
            try:
                message_task = self.message_queue.get(timeout=1.0)
                if message_task:
                    self._process_message_task(message_task)
                self.message_queue.task_done()
            except Empty:
                continue
            except Exception:
                pass

    def _process_message_task(self, task: Dict[str, Any]):
        try:
            if task["type"] == "send_message":
                connection_id = task["connection_id"]
                message = task["message"]
                self._send_message_secure(connection_id, message)
            elif task["type"] == "process_received":
                encrypted_data = task["data"]
                aes_key = task["aes_key"]
                connection_id = task["connection_id"]
                self._process_received_message(encrypted_data, aes_key, connection_id)
        except Exception:
            pass

    def _identity_rotation_loop(self):
        while True:
            try:
                time.sleep(self.identity_rotation_interval)
                if self.auto_rotate_identities and self.ephemeral_mode:
                    self._rotate_identity()
            except Exception:
                break

    def _rotate_identity(self):
        try:
            new_username = self.generate_random_username()
            old_username = self.username
            self.username = new_username
            self.ephemeral_identities.append(
                {
                    "old_username": old_username,
                    "new_username": new_username,
                    "rotation_time": time.time(),
                }
            )
        except Exception:
            pass

    def start_listener(self) -> int:
        try:
            preferred_ports = [
                8080,
                8081,
                8082,
                8083,
                8084,
                8085,
                8086,
                8087,
                8088,
                8089,
            ]

            for port in preferred_ports:
                try:
                    # Create listening socket and hidden service through Tor
                    print(f"[+] Creating hidden service on port {port}...")
                    self.listening_socket, self.onion_address = self.tor_wrapper.create_listening_socket(port)
                    self.listening_socket.settimeout(1.0)
                    self.listening_port = port
                    self.is_listening = True

                    listener_thread = threading.Thread(
                        target=self._listener_loop, daemon=True
                    )
                    listener_thread.start()

                    self._notify_server_of_port(port)
                    print(f"[+] Secure listener started on port {port}")
                    print(f"[+] Onion address: {self.onion_address}")
                    return port

                except OSError as e:
                    if self.listening_socket:
                        try:
                            self.listening_socket.close()
                        except:
                            pass
                    if port == preferred_ports[-1]:
                        print(f"[-] Could not bind to any port: {e}")
                        return 0
                    continue

        except Exception as e:
            print(f"[-] Listener startup failed: {e}")
            return 0

    def _listener_loop(self):
        while self.is_listening:
            try:
                if self.listening_socket:
                    client_socket, addr = self.listening_socket.accept()
                    self.client_socket = client_socket
                    print(f"[+] Tor connection accepted from: {addr}")
                    thread = threading.Thread(
                        target=self.handle_incoming_connection,
                        args=(client_socket, addr),
                        daemon=True,
                    )
                    thread.start()
            except socket.timeout:
                continue
            except Exception:
                if self.is_listening:
                    break

    def _notify_server_of_port(self, port: int):
        try:
            if not self.ensure_valid_session():
                return False

            data = {
                "username_hash": self.identity_hash,
                "session_token": self.session_token,
                "port": port,
                "client_id": self.unique_client_id,
                "onion_address": self.onion_address  # Send onion address to server
            }

            data = self.anonymize_metadata(data)

            response = requests.post(URL_SET_PORT, json=data, timeout=10)
            return response.status_code == 200

        except Exception:
            return False

    def handle_incoming_connection(self, client_sock, addr):
       connection_id = f"recv_{addr[0]}_{addr[1]}_{int(time.time())}"
       peer_username = "Unknown"

       try:
           client_sock.settimeout(15)

           # Receive initiator's public key with better error handling
           initiator_key_bytes = b""
           while len(initiator_key_bytes) < 32:
               chunk = client_sock.recv(32 - len(initiator_key_bytes))
               if not chunk:
                   print("[-] Failed to receive complete initiator public key")
                   return
               initiator_key_bytes += chunk

           initiator_key = initiator_key_bytes.hex().strip().lower()
           print(f"[DEBUG] Received initiator public key: {initiator_key[:16]}...")

           # CRITICAL: Verify we didn't receive our own key
           if initiator_key == self.public_key_hex.lower():
               print("[-] CRITICAL: Received our own public key from initiator")
               return

           # Send OUR public key (not the initiator's key!)
           client_sock.send(self.public_key_bytes)
           print(f"[DEBUG] Sent our public key: {self.public_key_hex[:16]}...")

           # Receive username length and username
           username_length_data = b""
           while len(username_length_data) < 4:
               chunk = client_sock.recv(4 - len(username_length_data))
               if not chunk:
                   print("[-] Failed to receive username length")
                   return
               username_length_data += chunk

           username_length = struct.unpack(">I", username_length_data)[0]
           print(f"[DEBUG] Received username length: {username_length}")
           if username_length > 100:
               print(f"[-] Username too long: {username_length} bytes (max 100)")
               return

           peer_username_data = b""
           while len(peer_username_data) < username_length:
               chunk = client_sock.recv(username_length - len(peer_username_data))
               if not chunk:
                   print("[-] Failed to receive complete username")
                   return
               peer_username_data += chunk

           peer_username = peer_username_data.decode()
           print(f"[DEBUG] Received peer username: {peer_username}")

           # Send our username
           username_bytes = self.username.encode()
           client_sock.send(struct.pack(">I", len(username_bytes)))
           client_sock.send(username_bytes)

           # Generate peer ID from initiator's key (not our key!)
           digest = hashes.Hash(hashes.SHA256())
           digest.update(initiator_key.encode())
           peer_id = digest.finalize().hex()

           if not self.verify_peer_public_key(
               peer_id, initiator_key, peer_username
           ):
               print("[-] Peer verification failed")
               return

           # Derive shared secret using initiator's key
           shared_secret = self.derive_shared_secret(initiator_key)
           if not shared_secret:
               print("[-] Failed to derive shared secret")
               return

           connection_id = f"recv_{peer_username}"
           print(f"[+] Establishing Tor connection {connection_id} with shared key {shared_secret.hex()[:16]}...")

           with self.lock:
               self.active_connections[connection_id] = {
                   "socket": client_sock,
                   "aes_key": shared_secret,
                   "role": "recipient",
                   "peer_info": {
                       "username": peer_username,
                       "peer_id": peer_id,
                       "public_key": initiator_key,
                       "address": addr,
                   },
                   "established": time.time(),
                   "verified": True,
                   "e2e_enabled": True,
                   "tor_routed": True
               }

           print(f"[+] Tor connection established successfully with {peer_username}")
           self._secure_message_loop(client_sock, shared_secret, connection_id)

       except Exception as e:
           print(f"[-] Incoming Tor connection error: {e}")
       finally:
           with self.lock:
               if connection_id in self.active_connections:
                   del self.active_connections[connection_id]
           try:
               client_sock.close()
           except:
               pass

    def _secure_message_loop(self, sock, aes_key, connection_id):
        try:
            sock.settimeout(0.5)
            while True:
                try:
                    with self.lock:
                        if connection_id not in self.active_connections:
                            break

                    header = sock.recv(4)
                    if not header:
                        break

                    if len(header) < 4:
                        continue

                    length = struct.unpack(">I", header)[0]
                    if length > MAX_MESSAGE_SIZE:
                        print("[-] Message too large")
                        break

                    encrypted_data = b""
                    while len(encrypted_data) < length:
                        chunk = sock.recv(min(4096, length - len(encrypted_data)))
                        if not chunk:
                            break
                        encrypted_data += chunk

                    if len(encrypted_data) == length:
                        self._process_received_message(
                            encrypted_data, aes_key, connection_id
                        )

                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    print("[-] Tor connection lost with peer")
                    break
                except Exception as e:
                    if "active_connections" in str(e):
                        break
                    print(f"[-] Message loop error: {e}")
                    continue

        except Exception as e:
            print(f"[-] Secure message loop fatal error: {e}")
        finally:
            with self.lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            try:
                sock.close()
            except:
                pass
            print(f"[-] Tor connection {connection_id} closed")

    def _send_message_secure(self, connection_id: str, message: str) -> bool:
        try:
            with self.lock:
                if connection_id not in self.active_connections:
                    return False
                conn = self.active_connections[connection_id]
                aes_key = conn["aes_key"]
                socket_obj = conn["socket"]

            encrypted_data = self.secure_protocol.encrypt_message(message, aes_key)
            if not encrypted_data:
                return False

            header = struct.pack(">I", len(encrypted_data))
            socket_obj.sendall(header + encrypted_data)

            timestamp = time.time()
            with self.lock:
                self.message_history.append(
                    {
                        "sender": self.username,
                        "text": message,
                        "timestamp": timestamp,
                        "connection_id": connection_id,
                        "direction": "outgoing",
                    }
                )

            if self.current_chat_peer:
                formatted_time = time.strftime("%H:%M:%S", time.localtime(timestamp))
                print(f"[{formatted_time}] You: {message}")

            return True

        except (BrokenPipeError, ConnectionResetError):
            with self.lock:
                if connection_id in self.active_connections:
                    del self.active_connections[connection_id]
            return False
        except Exception as e:
            print(f"[-] Send message error: {e}")
            return False

    def _process_received_message(
        self, encrypted_data: bytes, aes_key: bytes, connection_id: str
    ):
        if not encrypted_data or len(encrypted_data) < 28:
            return

        try:
            decrypted_content = self.secure_protocol.decrypt_message(
                encrypted_data, aes_key
            )
            if not decrypted_content:
                return

            peer_username = "Unknown"
            try:
                with self.lock:
                    if connection_id not in self.active_connections:
                        return
                    peer_info = self.active_connections[connection_id].get(
                        "peer_info", {}
                    )
                    peer_username = peer_info.get("username", "Unknown")
            except Exception:
                return

            timestamp = time.time()
            with self.lock:
                self.message_history.append(
                    {
                        "sender": peer_username,
                        "text": decrypted_content,
                        "timestamp": timestamp,
                        "connection_id": connection_id,
                        "direction": "incoming",
                    }
                )

            self.chat_interface.receive_message(peer_username, decrypted_content)

        except Exception as e:
            print(f"[-] Error processing received message: {e}")

    def send_message(self, connection_id, message):
        if not message or len(message.strip()) == 0:
            return False
        try:
            self.message_queue.put(
                {
                    "type": "send_message",
                    "connection_id": connection_id,
                    "message": message,
                }
            )
            return True
        except Exception as q_err:
            print(f"[-] Queue error: {q_err}")
            return False

    def derive_shared_secret(self, peer_public_key_hex):
        if not peer_public_key_hex or len(peer_public_key_hex) != 64:
            print("[-] Shared secret error: Invalid peer key hex.")
            return None
        try:
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(peer_public_key_hex)
            )
            shared_secret = self.private_key.exchange(peer_public_key)

            key_material = sorted([self.public_key_hex, peer_public_key_hex])
            combined_keys = "".join(key_material).encode()
            salt = hashlib.sha256(combined_keys).digest()[:16]

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"p2p_secure_e2e_v2",
            )
            derived_key = hkdf.derive(shared_secret)

            return derived_key
        except ValueError as key_ve:
            print(f"[-] Shared secret key error: {key_ve}")
            return None
        except Exception as der_err:
            print(f"[-] Unexpected derivation error: {der_err}")
            return None

    def verify_peer_public_key(self, peer_id, received_public_key, peer_username=None):
        try:
            with self.lock:
                if peer_id in self.peer_directory:
                    stored_key = self.peer_directory[peer_id]["public_key"]
                    if stored_key and stored_key != received_public_key:
                        print(
                            f"[!] Security Alert: Key change detected for {self.peer_directory[peer_id]['username']}"
                        )
                        return False

                username = peer_username if peer_username else f"User_{peer_id[:8]}"
                self.peer_directory[peer_id] = {
                    "public_key": received_public_key,
                    "username": username,
                    "verified": True,
                    "first_seen": time.time(),
                    "last_verified": time.time(),
                }
                self.username_to_peer_map[username] = peer_id

                print(f"[+] Verified peer: {username} (ID: {peer_id[:16]}...)")
                return True
        except Exception as e:
            print(f"[-] Key verification failed: {e}")
            return False

    def get_self_ip(self):
        # Return Tor exit node IP or onion address
        if self.onion_address:
            return self.onion_address
        tor_ip = self.tor_instance.get_tor_ip()
        if tor_ip:
            return tor_ip
        # Fallback to regular IP detection
        for i in range(len(URL_IP)):
            _var = requests.get(URL_IP[i])
            if _var.status_code == 200:
                return _var.text
            else:
                continue

    def request_connection(self, target_identity_hash: str) -> Optional[Dict]:
        try:
            if not self.ensure_valid_session():
                return None

            data = {
                "username_hash": self.identity_hash,
                "target_username_hash": target_identity_hash,
                "session_token": self.session_token,
                "IP" : self.get_self_ip(),
                "onion_address": self.onion_address
            }

            for attempt in range(3):
                try:
                    response = requests.post(
                        URL_REQUEST_CONNECTION, json=data, timeout=10
                    )

                    if response.status_code == 200:
                        result = response.json()
                        if result.get("status") == "connection_ready":
                            return result
                        else:
                            return None
                    else:
                        error_msg = response.json().get("error", "Unknown error")
                        if "not online" in error_msg.lower():
                            return None

                except requests.Timeout:
                    time.sleep(2)
                    continue
                except Exception:
                    break

            return None

        except Exception:
            return None

    def _username_to_identity_hash(self, username: str) -> Optional[str]:
        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(username.encode())
            digest.update(os.urandom(16))
            return digest.finalize().hex()
        except Exception:
            return None

    def _peer_id_to_identity_hash(self, peer_id: str) -> Optional[str]:
        try:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(peer_id.encode())
            return digest.finalize().hex()
        except Exception:
            return None

    def connect_to_username(self, username: str, target_username: str) -> Optional[str]:
        try:
            if not self.ensure_valid_session():
                return None

            with self.lock:
                self_user_hash = self._username_to_identity_hash(username)
                if not self_user_hash:
                    return None

            target_identity_hash = self._username_to_identity_hash(target_username)
            if not target_identity_hash:
                return None

            payload = {
                "username_hash": self_user_hash,
                "target_username_hash": target_identity_hash,
                "session_token": self.session_token,
                "IP": self.get_self_ip(),
                "onion_address": self.onion_address
            }

            request = requests.post(URL_REQUEST_CONNECTION, params=payload)
            if request.status_code == 200 and request.json().get("status") ==  "connection_ready":
                target_peer_id = request.json().get("target_peer_id")
                self.connect_to_peer_direct(target_peer_id, target_identity_hash)
            else:
                return None

        except Exception:
            return None

    def connect_to_peer_id(self, target_peer_id: str) -> Optional[str]:
        try:
            if not self.ensure_valid_session():
                return None

            with self.lock:
                if target_peer_id not in self.peer_directory:
                    return None

                peer_info = self.peer_directory[target_peer_id]
                target_identity_hash = self._peer_id_to_identity_hash(target_peer_id)

            if not target_identity_hash:
                return None

            return self.connect_to_peer_direct(target_peer_id, target_identity_hash)

        except Exception:
            return None

    def connect_to_peer_direct(self, target_peer_id, target_identity_hash):
       try:
           if not self.ensure_valid_session():
               print("[-] Session validation failed")
               return None

           existing_conn = None
           with self.lock:
               for conn_id, conn_info in self.active_connections.items():
                   if conn_info["peer_info"]["peer_id"] == target_peer_id:
                       existing_conn = conn_id
                       break

           if existing_conn:
               print(f"[+] Using existing Tor connection: {existing_conn}")
               return existing_conn

           # Get target's actual public key from peer directory FIRST
           with self.lock:
               if target_peer_id in self.peer_directory:
                   actual_target_public_key = self.peer_directory[target_peer_id].get("public_key")
               else:
                   actual_target_public_key = None

           connection_info = self.request_connection(target_identity_hash)
           if not connection_info:
               print("[-] Server connection request failed")
               return None

           target_port = connection_info.get("target_listening_port")
           target_address = connection_info.get("onion_address")
           if not target_address:
               target_address = connection_info.get("IP", "127.0.0.1")
           server_provided_key = connection_info.get("target_public_key")

           if not target_port or not server_provided_key:
               print("[-] Missing connection info from server")
               return None

           username = self.peer_directory.get(target_peer_id, {}).get(
               "username", f"User_{target_peer_id[:8]}"
           )

           is_onion = target_address.endswith('.onion')

           if is_onion:
               print(f"[+] Connecting to {username} via Tor at {target_address}:80")
               sock = self.tor_wrapper.connect_to_onion(target_address, 80, timeout=30)
           else:
               print(f"[+] Connecting to {username} via Tor at {target_address}:{target_port}")
               sock = self.tor_wrapper.connect_to_ip(target_address, target_port, timeout=30)

           if not sock:
               print("[-] Failed to establish Tor connection")
               return None

           # Send OUR public key first
           sock.send(self.to_send)
           print(f"[DEBUG] Sent our public key: {self.public_key_hex[:16]}...")

           # Receive PEER's public key
           try:
               target_key = sock.recv(32)
               print("Received target public key", target_key)
               if len(target_key) != 32:
                   print("[-] Failed to receive valid target public key")
                   # sock.close()
                   # return None

               peer_sent_key = target_key.hex().strip().lower()
               print(f"[DEBUG] Received peer public key: {peer_sent_key[:16]}...")

           except socket.timeout:
               print("[-] Timeout receiving peer public key")
               sock.close()
               return None

           # Send our username
           username_bytes = self.username.encode()
           try:
               sock.send(struct.pack(">I", len(username_bytes)))
               sock.send(username_bytes)
           except Exception as e:
               print(f"[-] Failed to send username: {e}")
               sock.close()
               return None

           # Receive peer's username
           try:
               username_length_data = b""
               while len(username_length_data) < 4:
                   chunk = sock.recv(4 - len(username_length_data))
                   if not chunk:
                       print("[-] Failed to receive username length")
                       sock.close()
                       return None
                   username_length_data += chunk

               username_length = struct.unpack(">I", username_length_data)[0]
               if username_length > 100:
                   print("[-] Username too long")
                   sock.close()
                   return None

               received_username_bytes = b""
               while len(received_username_bytes) < username_length:
                   chunk = sock.recv(username_length - len(received_username_bytes))
                   if not chunk:
                       print("[-] Failed to receive complete username")
                       sock.close()
                       return None
                   received_username_bytes += chunk

               received_username = received_username_bytes.decode()
               print(f"[DEBUG] Received peer username: {received_username}")

           except Exception as e:
               print(f"[-] Failed to receive peer username: {e}")
               sock.close()
               return None

           # Normalize keys for comparison
           server_provided_key = server_provided_key.strip().lower()

           # CRITICAL: Verify we didn't receive our own key back
           if target_key.hex() != server_provided_key:
               print(f"[-] Key mismatch with server info")
               print(f"    Server provided: {target_key[:16]}...")
               print(f"    Peer sent: {target_key.hex()[:16]}...")
               try:
                   option = str(input("Do you want to continue without key verification? (y/n) (recomended: do not, potential MITM): "))
                   if option.lower() == 'y':
                       print("[+] Continuing without key verification")
                   elif option.lower() == 'n':
                       print("[-] Key verification failed")
                       sock.close()
                       return None
                   else:
                       print("Invalid option, defaulting to no")
                       print("\n")
                       print("Connection closed")
                       sock.close()
                       return None
               except Exception as e:
                   print(f"[-] Failed to get user input: {e}")
                   sock.close()
                   return None
               return None

           # VALIDATION: Check if we have the actual target public key from discovery
           if actual_target_public_key:
               actual_target_public_key = actual_target_public_key.strip().lower()
               if peer_sent_key != actual_target_public_key:
                   print(f"[-] CRITICAL: Key mismatch with discovered peer key")
                   print(f"    Discovered: {actual_target_public_key[:16]}...")
                   print(f"    Peer sent: {peer_sent_key[:16]}...")
                   sock.close()
                   return None
               print(f"[+] Key validated against discovered peer directory")
           else:
               # If no prior key, verify against server-provided key
               if target_key.hex() != server_provided_key:
                   print(f"[-] CRITICAL: Key mismatch with server-provided key")
                   print(f"    Server provided: {server_provided_key[:16]}...")
                   print(f"    Peer sent: {peer_sent_key[:16]}...")
                   try:
                       option = str(input("Do you want to continue without key verification? (y/n) (recomended: do not, potential MITM): "))
                       if option.lower() == 'y':
                           print("[+] Continuing without key verification")
                       elif option.lower() == 'n':
                           print("[-] Key verification failed")
                           sock.close()
                           return None
                       else:
                           print("Invalid option, defaulting to no")
                           print("\n")
                           print("Connection closed")
                           sock.close()
                           return None
                   except Exception as e:
                       print(f"[-] Failed to get user input: {e}")
                       sock.close()
                       return None
                   sock.close()
                   return None
               print(f"[+] Key validated against server-provided key")

           if not self.verify_peer_public_key(
               target_peer_id, peer_sent_key, received_username
           ):
               print("[-] Peer verification failed")
               sock.close()
               return None

           shared_secret = self.derive_shared_secret(peer_sent_key)
           if not shared_secret:
               print("[-] Failed to derive shared secret")
               sock.close()
               return None

           connection_id = f"init_{received_username}"
           print(f"[+] Establishing Tor connection {connection_id} with shared key {shared_secret.hex()[:16]}...")

           with self.lock:
               self.active_connections[connection_id] = {
                   "socket": sock,
                   "aes_key": shared_secret,
                   "role": "initiator",
                   "peer_info": {
                       "username": received_username,
                       "peer_id": target_peer_id,
                       "public_key": peer_sent_key,
                       "address": (target_address, target_port),
                   },
                   "established": time.time(),
                   "verified": True,
                   "e2e_enabled": True,
                   "tor_routed": True
               }

           thread = threading.Thread(
               target=self._secure_message_loop,
               args=(sock, shared_secret, connection_id),
               daemon=True
           )
           thread.start()

           print(f"[+] Tor connection established successfully with {received_username}")
           return connection_id

       except Exception as e:
           print(f"[-] Tor connection error: {e}")
           try:
               sock.close()
           except:
               pass
           return None

    def get_connection_by_username(self, username: str) -> Optional[str]:
        try:
            with self.lock:
                peer_id = self.username_to_peer_map.get(username)
                if not peer_id:
                    return None

            for conn_id, conn_info in self.active_connections.items():
                if conn_info.get("peer_info", {}).get("peer_id") == peer_id:
                    return conn_id
            return None
        except Exception:
            return None

    def check_for_connection(self, username_hash: str, peer_id: str) -> Optional[str]:
        try:
            while(True):
                with self.lock:
                    for conn_id, conn_info in self.active_connections.items():
                        if conn_info.get("peer_info", {}).get("peer_id") == peer_id:
                            print(f"[+] Found existing active Tor connection: {conn_id}")
                            return conn_id


                if not self.ensure_valid_session():
                    return None

                params = {
                    "username_hash": username_hash,
                    "peer_id": peer_id,
                    "session_token": self.session_token,
                }

                time.sleep(10)
                response = requests.get(URL_CHECK_FOR_CONNECTION, params=params, timeout=10)
                if response.status_code != 200:
                    continue

                result = response.json()
                status = result.get("status")
                if status != "ready":
                    continue

                target_port = result.get("target_listening_port")
                target_address = result.get("onion_address")
                if not target_address:
                    target_address = result.get("IP")
                target_public_key = result.get("target_public_key")
                if not target_port or not target_public_key:
                    print("[-] Incomplete connection info from server")
                    return None


                print(f"[+] Peer ready. Connecting via Tor to {peer_id} at {target_address}:{target_port}...")
                return self.connect_to_peer_direct(peer_id, username_hash)

        except Exception as e:
            print(f"[-] check_for_connection error: {e}")
            return None

    def start_chat(self, connection_id_or_username):
        connection_id = None
        username = None
        try:
            if connection_id_or_username.startswith(("init_", "recv_")):
                connection_id = connection_id_or_username
                with self.lock:
                    if connection_id not in self.active_connections:
                        return
                    username = self.active_connections[connection_id]["peer_info"]["username"]
            else:
                username = connection_id_or_username
                connection_id = self.get_connection_by_username(username)
                if not connection_id:
                    return

            self.current_chat_peer = username

            with self.lock:
                recent = [m for m in self.message_history if m.get("connection_id") == connection_id][-50:]

            for msg in recent:
                ts = time.strftime("%H:%M", time.localtime(msg.get("timestamp", time.time())))
                who = "You" if msg.get("sender") == self.username else msg.get("sender")
                print(f"[{ts}] {who}: {msg.get('text') or msg.get('content')}")

            self.chat_active = True

            def input_thread():
                while self.chat_active:
                    try:
                        text = input("You: ").strip()
                        if not text:
                            continue
                        if text.lower() in ("/exit", "exit"):
                            self.chat_active = False
                            break
                        if text.lower() == "/status":
                            self.verify_connection_security(connection_id)
                            continue
                        if text.lower().startswith("/file "):
                            path = text[6:].strip()
                            if os.path.exists(path):
                                threading.Thread(target=self.send_file, args=(connection_id, path), daemon=True).start()
                            continue

                        sent = self.send_message(connection_id, text)
                        if not sent:
                            print("[!] Send failed; will retry shortly")
                            time.sleep(0.2)
                            continue
                        self.chat_interface.add_message("self", text)

                    except Exception as e:
                        print(f"[!] Chat input error: {e}")
                        self.chat_active = False
                        break

            t = threading.Thread(target=input_thread, daemon=True)
            t.start()

            while self.chat_active:
                time.sleep(0.1)

            self.current_chat_peer = None
            self.chat_active = False

        except Exception as e:
            print(f"[!] start_chat error: {e}")
            self.chat_active = False

    def verify_connection_security(self, connection_id):
        try:
            with self.lock:
                if connection_id in self.active_connections:
                    conn = self.active_connections[connection_id]
                    print(f"\n[Security Verification]")
                    print(f"Peer: {conn['peer_info']['username']}")
                    print(
                        f"E2E Encrypted: {'Yes' if conn.get('e2e_enabled') else 'No'}"
                    )
                    print(f"Verified: {'Yes' if conn.get('verified') else 'No'}")
                    print(f"Tor Routed: {'Yes' if conn.get('tor_routed') else 'No'}")
                    print(f"Connection Time: {time.ctime(conn['established'])}")
                    print(f"Duration: {time.time() - conn['established']:.0f} seconds")
        except Exception:
            pass

    def show_connections(self):
        try:
            with self.lock:
                if not self.active_connections:
                    print("\n[!] No active connections")
                    return

                print(f"\n{'=' * 90}")
                print(f"[+] Active Tor Connections ({len(self.active_connections)}):")
                print(f"{'=' * 90}")

                for conn_id, conn_info in self.active_connections.items():
                    username = conn_info["peer_info"]["username"]
                    role = conn_info["role"]
                    peer_id = conn_info["peer_info"]["peer_id"][:16]
                    established = time.ctime(conn_info["established"])
                    e2e_status = "✓" if conn_info.get("e2e_enabled") else "✗"
                    verified = "✓" if conn_info.get("verified") else "✗"
                    tor_status = "✓" if conn_info.get("tor_routed") else "✗"

                    print(
                        f"  [E2E:{e2e_status} V:{verified} Tor:{tor_status}] {username:<20} ({role:<9}) | ID: {peer_id}... | Est: {established}"
                    )

                print(f"{'=' * 90}")
        except Exception:
            pass

    def multi_chat_interface(self):
        try:
            print(f"\n{'=' * 60}")
            print("[+] MULTI-CHAT INTERFACE - Secure E2E + Tor Connections")
            print(f"{'=' * 60}")

            while True:
                with self.lock:
                    active_conns = list(self.active_connections.items())

                if not active_conns:
                    print("[!] No active connections")
                    print("1. Connect to new peer")
                    print("2. Return to main menu")
                    choice = input("Select option: ").strip()
                    if choice == "1":
                        return
                    elif choice == "2":
                        return
                    continue

                print(f"\nActive E2E + Tor Connections ({len(active_conns)}):")
                for i, (conn_id, conn_info) in enumerate(active_conns, 1):
                    username = conn_info["peer_info"]["username"]
                    e2e_status = "✓" if conn_info.get("e2e_enabled") else "✗"
                    tor_status = "✓" if conn_info.get("tor_routed") else "✗"
                    role = conn_info["role"]
                    print(f"  {i}. [E2E:{e2e_status} Tor:{tor_status}] {username} ({role}) - {conn_id}")

                print(f"\nOptions:")
                print("1-{}. Start chat with connection".format(len(active_conns)))
                print("c. Connect to new peer")
                print("s. Security status overview")
                print("x. Return to main menu")

                choice = input("\nSelect option: ").strip().lower()

                if choice == "x":
                    return
                elif choice == "c":
                    self._connect_new_peer_from_chat()
                elif choice == "s":
                    self._show_security_overview()
                elif choice.isdigit():
                    conn_num = int(choice)
                    if 1 <= conn_num <= len(active_conns):
                        conn_id, conn_info = active_conns[conn_num - 1]
                        self.start_chat(conn_id)
        except Exception:
            pass

    def _connect_new_peer_from_chat(self):
        try:
            print("\n[+] New Tor Connection:")
            print("1. By username")
            print("2. By Peer ID")
            print("3. Discover online peers")
            print("4. Cancel")

            choice = input("Select option: ").strip()
            if choice == "1":
                username = input("Enter username: ").strip()
                if username:
                    conn_id = self.connect_to_username(username)
                    if conn_id:
                        self.start_chat(conn_id)
            elif choice == "2":
                peer_id = input("Enter Peer ID: ").strip()
                if peer_id:
                    conn_id = self.connect_to_peer_id(peer_id)
                    if conn_id:
                        self.start_chat(conn_id)
            elif choice == "3":
                online_peers = self.discover_online_peers()
                if online_peers:
                    print(f"\n[+] Found {len(online_peers)} online peers:")
                    for i, peer in enumerate(online_peers, 1):
                        print(
                            f"  {i}. User_{peer['peer_id'][:8]} (ID: {peer['peer_id'][:16]}...)"
                        )

                    selection = input("\nSelect peer number or 'c' to cancel: ").strip()
                    if selection.isdigit():
                        peer_num = int(selection)
                        if 1 <= peer_num <= len(online_peers):
                            peer = online_peers[peer_num - 1]
                            conn_id = self.connect_to_peer_direct(
                                peer["peer_id"], peer["username_hash"]
                            )
                            if conn_id:
                                self.start_chat(conn_id)
        except Exception:
            pass

    def _show_security_overview(self):
        try:
            with self.lock:
                total_conns = len(self.active_connections)
                e2e_conns = sum(
                    1
                    for conn in self.active_connections.values()
                    if conn.get("e2e_enabled")
                )
                verified_conns = sum(
                    1
                    for conn in self.active_connections.values()
                    if conn.get("verified")
                )
                tor_conns = sum(
                    1
                    for conn in self.active_connections.values()
                    if conn.get("tor_routed")
                )

            print(f"\n{'=' * 50}")
            print("[SECURITY OVERVIEW]")
            print(f"{'=' * 50}")
            print(f"Total Connections: {total_conns}")
            print(f"E2E Encrypted: {e2e_conns}")
            print(f"Verified Peers: {verified_conns}")
            print(f"Tor Routed: {tor_conns}")
            print(f"Known Peers: {len(self.peer_directory)}")
            print(f"Message History: {len(self.message_history)}")
            print(f"Session ID: {self.session_id}")
            print(f"Onion Address: {self.onion_address if self.onion_address else 'Not available'}")
            print(
                f"Identity Protection: {'Enabled' if self.ephemeral_mode else 'Disabled'}"
            )
            print(
                f"Auto Rotation: {'Enabled' if self.auto_rotate_identities else 'Disabled'}"
            )

            if self.active_connections:
                print(f"\n[CONNECTION SECURITY]")
                for conn_id, conn_info in self.active_connections.items():
                    username = conn_info["peer_info"]["username"]
                    e2e = "✓" if conn_info.get("e2e_enabled") else "✗"
                    verified = "✓" if conn_info.get("verified") else "✗"
                    tor = "✓" if conn_info.get("tor_routed") else "✗"
                    duration = time.time() - conn_info["established"]
                    print(
                        f"  {username}: E2E[{e2e}] Verified[{verified}] Tor[{tor}] Duration: {duration:.0f}s"
                    )
        except Exception:
            pass

    def print_status_line(self, message=""):
        try:
            with self.lock:
                connection_count = len(self.active_connections)
                e2e_count = sum(
                    1
                    for conn in self.active_connections.values()
                    if conn.get("e2e_enabled", False)
                )
                tor_count = sum(
                    1
                    for conn in self.active_connections.values()
                    if conn.get("tor_routed", False)
                )

            status = f"Connections: {connection_count} (E2E: {e2e_count}, Tor: {tor_count})"
            if message:
                print(f"\r{message:<60} {status}")
            else:
                print(f"\r{'':<60} {status}")
        except Exception:
            pass

    def clear_session_data(self):
        try:
            if self.ephemeral_mode:
                self.peer_directory.clear()
                self.username_to_peer_map.clear()
                self.message_history.clear()
                self.ephemeral_identities.clear()
        except Exception:
            pass

    def shutdown(self):
        try:
            self.traffic_manager.stop_traffic_obfuscation()
            self.is_listening = False

            with self.lock:
                for conn_id, conn_info in self.active_connections.items():
                    try:
                        conn_info["socket"].close()
                    except:
                        pass
                self.active_connections.clear()

            if self.listening_socket:
                try:
                    self.listening_socket.close()
                except:
                    pass

            # Shutdown Tor
            print("[+] Shutting down Tor...")
            shutdown_tor()

        except Exception:
            pass
