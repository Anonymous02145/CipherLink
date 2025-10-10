from stem.control import Controller
import stem.process
import socks
import socket
import threading
import time
import os
from typing import Optional, Tuple

PORT = 9000

class TOR:
    def __init__(self, control_port=9051, socks_port=9050):
        self.control_port = control_port
        self.socks_port = socks_port
        self.control = None
        self.tor_process = None
        self.hidden_service_dir = None
        self.onion_address = None
        self.is_running = False

    def start_tor(self):
        """Start Tor process and authenticate"""
        try:
            # Try to connect to existing Tor instance
            self.control = Controller.from_port(port=self.control_port)
            self.control.authenticate()
            self.is_running = True
            print("[+] Connected to existing Tor instance")
        except:
            try:
                # Launch new Tor process
                print("[+] Starting new Tor process...")
                self.tor_process = stem.process.launch_tor_with_config(
                    config={
                        "SocksPort": str(self.socks_port),
                        "ControlPort": str(self.control_port),
                        "CookieAuthentication": "1"
                    },
                    timeout=60,
                    take_ownership=True
                )
                time.sleep(5)  # Wait for Tor to fully start
                self.control = Controller.from_port(port=self.control_port)
                self.control.authenticate()
                self.is_running = True
                print("[+] Tor process started successfully")
            except Exception as e:
                print(f"[-] Failed to start Tor: {e}")
                raise

    def create_hidden_service(self, local_port: int) -> Optional[str]:
        """Create an ephemeral hidden service for the given local port"""
        try:
            if not self.is_running:
                self.start_tor()

            response = self.control.create_ephemeral_hidden_service(
                {80: local_port},  # Map port 80 on onion to local_port
                key_type="NEW",
                key_content="ED25519-V3",
                await_publication=True
            )
            self.onion_address = response.service_id + ".onion"
            print(f"[+] Hidden service created: {self.onion_address}")
            return self.onion_address
        except Exception as e:
            print(f"[-] Failed to create hidden service: {e}")
            return None

    def create_tor_socket(self) -> socket.socket:
        """Create a socket configured to use Tor SOCKS proxy"""
        try:
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, "127.0.0.1", self.socks_port)
            return s
        except Exception as e:
            print(f"[-] Failed to create Tor socket: {e}")
            raise

    def wrap_existing_socket(self, sock: socket.socket) -> socket.socket:
        """Wrap an existing socket to route through Tor"""
        try:
            # Note: This creates a new tor socket, as wrapping existing sockets is complex
            tor_sock = self.create_tor_socket()
            return tor_sock
        except Exception as e:
            print(f"[-] Failed to wrap socket: {e}")
            raise

    def connect_through_tor(self, address: str, port: int, timeout: int = 15) -> Optional[socket.socket]:
        """Create a connection through Tor to the specified address"""
        try:
            sock = self.create_tor_socket()
            sock.settimeout(timeout)
            print(f"[+] Connecting through Tor to {address}:{port}")
            sock.connect((address, port))
            return sock
        except Exception as e:
            print(f"[-] Tor connection failed: {e}")
            return None

    def get_tor_ip(self) -> Optional[str]:
        """Get the current Tor exit node IP"""
        try:
            import requests
            proxies = {
                'http': f'socks5h://127.0.0.1:{self.socks_port}',
                'https': f'socks5h://127.0.0.1:{self.socks_port}'
            }
            response = requests.get('https://api.ipify.org', proxies=proxies, timeout=10)
            return response.text
        except Exception as e:
            print(f"[-] Failed to get Tor IP: {e}")
            return None

    def shutdown(self):
        """Shutdown Tor process and controller"""
        try:
            if self.control:
                self.control.close()
            if self.tor_process:
                self.tor_process.kill()
            self.is_running = False
            print("[+] Tor shutdown complete")
        except Exception as e:
            print(f"[-] Error during Tor shutdown: {e}")


class TorSocketWrapper:
    """Wrapper class to make Tor sockets compatible with existing code"""

    def __init__(self, tor_instance: TOR):
        self.tor = tor_instance
        self.socket = None
        self.is_onion = False

    def create_listening_socket(self, port: int) -> Tuple[socket.socket, Optional[str]]:
        """Create a regular listening socket and hidden service"""
        try:
            # Create regular socket for local listening
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', port))
            sock.listen(10)

            # Create hidden service pointing to this port
            onion_address = self.tor.create_hidden_service(port)

            return sock, onion_address
        except Exception as e:
            print(f"[-] Failed to create listening socket: {e}")
            raise

    def connect_to_onion(self, onion_address: str, port: int = 80, timeout: int = 15) -> Optional[socket.socket]:
        """Connect to an onion address through Tor"""
        return self.tor.connect_through_tor(onion_address, port, timeout)

    def connect_to_ip(self, ip_address: str, port: int, timeout: int = 15) -> Optional[socket.socket]:
        """Connect to regular IP through Tor"""
        return self.tor.connect_through_tor(ip_address, port, timeout)


# Global Tor instance
_global_tor_instance = None

def get_tor_instance() -> TOR:
    """Get or create global Tor instance"""
    global _global_tor_instance
    if _global_tor_instance is None:
        _global_tor_instance = TOR()
        try:
            _global_tor_instance.start_tor()
        except Exception as e:
            print(f"[-] Failed to initialize Tor: {e}")
            raise
    return _global_tor_instance


def initialize_tor() -> TOR:
    """Initialize and return Tor instance"""
    return get_tor_instance()


def shutdown_tor():
    """Shutdown global Tor instance"""
    global _global_tor_instance
    if _global_tor_instance:
        _global_tor_instance.shutdown()
        _global_tor_instance = None
