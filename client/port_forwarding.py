import miniupnpc
import socket
import threading
import time
from typing import Optional, Tuple
import requests

class PortForwardingManager:
    """Manages UPnP port forwarding for public IP connections"""

    def __init__(self):
        self.upnp = None
        self.forwarded_ports = {}  # {local_port: (external_port, protocol)}
        self.lock = threading.Lock()
        self.public_ip = None

    def initialize_upnp(self) -> bool:
        """Initialize UPnP connection to router"""
        try:
            self.upnp = miniupnpc.UPnP()
            self.upnp.discoverdelay = 200

            print("[+] Discovering UPnP devices...")
            devices = self.upnp.discover()

            if devices == 0:
                print("[-] No UPnP devices found")
                return False

            print(f"[+] Found {devices} UPnP device(s)")

            # Select IGD (Internet Gateway Device)
            self.upnp.selectigd()

            # Get external IP
            self.public_ip = self.upnp.externalipaddress()
            print(f"[+] External IP: {self.public_ip}")

            return True

        except Exception as e:
            print(f"[-] UPnP initialization failed: {e}")
            return False

    def add_port_forward(self, local_port: int, external_port: Optional[int] = None,
                        protocol: str = 'TCP', description: str = 'CipherLink') -> Optional[int]:
        """
        Add a port forwarding rule

        Args:
            local_port: Local port to forward to
            external_port: External port (if None, uses same as local_port)
            protocol: 'TCP' or 'UDP'
            description: Description for the forwarding rule

        Returns:
            External port number if successful, None otherwise
        """
        try:
            if not self.upnp:
                if not self.initialize_upnp():
                    return None

            if external_port is None:
                external_port = local_port

            # Get local IP
            local_ip = self._get_local_ip()

            with self.lock:
                # Check if port is already forwarded
                if local_port in self.forwarded_ports:
                    print(f"[!] Port {local_port} already forwarded")
                    return self.forwarded_ports[local_port][0]

                # Try to add port mapping
                print(f"[+] Adding port forward: {external_port} -> {local_ip}:{local_port} ({protocol})")

                result = self.upnp.addportmapping(
                    external_port,      # external port
                    protocol,           # protocol (TCP/UDP)
                    local_ip,          # internal host
                    local_port,        # internal port
                    description,       # description
                    ''                 # remote host (empty = any)
                )

                if result:
                    self.forwarded_ports[local_port] = (external_port, protocol)
                    print(f"[+] Port forwarding successful: {self.public_ip}:{external_port} -> {local_ip}:{local_port}")
                    return external_port
                else:
                    print(f"[-] Port forwarding failed for port {external_port}")
                    return None

        except Exception as e:
            print(f"[-] Error adding port forward: {e}")
            return None

    def remove_port_forward(self, local_port: int) -> bool:
        """Remove a port forwarding rule"""
        try:
            if not self.upnp:
                return False

            with self.lock:
                if local_port not in self.forwarded_ports:
                    print(f"[!] Port {local_port} not in forwarded ports")
                    return False

                external_port, protocol = self.forwarded_ports[local_port]

                print(f"[+] Removing port forward: {external_port} ({protocol})")

                result = self.upnp.deleteportmapping(external_port, protocol)

                if result:
                    del self.forwarded_ports[local_port]
                    print(f"[+] Port forward removed: {external_port}")
                    return True
                else:
                    print(f"[-] Failed to remove port forward: {external_port}")
                    return False

        except Exception as e:
            print(f"[-] Error removing port forward: {e}")
            return False

    def remove_all_forwards(self):
        """Remove all port forwarding rules"""
        with self.lock:
            ports = list(self.forwarded_ports.keys())

        for port in ports:
            self.remove_port_forward(port)

    def get_external_ip(self) -> Optional[str]:
        """Get public IP address"""
        if self.public_ip:
            return self.public_ip

        # Fallback to HTTP services
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text.strip()
        except:
            try:
                response = requests.get('https://ifconfig.me/ip', timeout=5)
                return response.text.strip()
            except:
                return None

    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Create a socket to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"

    def list_forwards(self):
        """List all active port forwards"""
        with self.lock:
            if not self.forwarded_ports:
                print("[!] No active port forwards")
                return

            print(f"\n{'='*60}")
            print(f"[+] Active Port Forwards ({len(self.forwarded_ports)}):")
            print(f"{'='*60}")

            for local_port, (external_port, protocol) in self.forwarded_ports.items():
                print(f"  {self.public_ip}:{external_port} ({protocol}) -> 127.0.0.1:{local_port}")

            print(f"{'='*60}")

    def verify_forward(self, external_port: int, protocol: str = 'TCP') -> bool:
        """Verify that a port forward is active"""
        try:
            if not self.upnp:
                return False

            # Get port mapping info
            result = self.upnp.getspecificportmapping(external_port, protocol)
            return result is not None

        except Exception as e:
            print(f"[-] Error verifying port forward: {e}")
            return False


class ConnectionTracker:
    """Track connections and cleanup port forwards when they close"""

    def __init__(self, port_manager: PortForwardingManager):
        self.port_manager = port_manager
        self.connection_ports = {}  # {connection_id: local_port}
        self.port_ref_count = {}    # {local_port: count}
        self.lock = threading.Lock()

    def register_connection(self, connection_id: str, local_port: int):
        """Register a connection using a forwarded port"""
        with self.lock:
            self.connection_ports[connection_id] = local_port
            self.port_ref_count[local_port] = self.port_ref_count.get(local_port, 0) + 1
            print(f"[+] Registered connection {connection_id} on port {local_port} (refs: {self.port_ref_count[local_port]})")

    def unregister_connection(self, connection_id: str):
        """Unregister a connection and cleanup port if no more references"""
        with self.lock:
            if connection_id not in self.connection_ports:
                return

            local_port = self.connection_ports[connection_id]
            del self.connection_ports[connection_id]

            # Decrease reference count
            if local_port in self.port_ref_count:
                self.port_ref_count[local_port] -= 1
                print(f"[+] Unregistered connection {connection_id} from port {local_port} (refs: {self.port_ref_count[local_port]})")

                # If no more connections using this port, remove forward
                if self.port_ref_count[local_port] <= 0:
                    del self.port_ref_count[local_port]
                    print(f"[+] No more connections on port {local_port}, removing forward...")
                    self.port_manager.remove_port_forward(local_port)

    def cleanup_all(self):
        """Cleanup all connections and port forwards"""
        with self.lock:
            connection_ids = list(self.connection_ports.keys())

        for conn_id in connection_ids:
            self.unregister_connection(conn_id)



class PublicIPConnectionManager:
    """Manages public IP connections with automatic port forwarding"""

    def __init__(self):
        self.port_manager = PortForwardingManager()
        self.connection_tracker = ConnectionTracker(self.port_manager)
        self.use_public_ip = False
        self.use_tor = True

    def enable_public_ip_mode(self) -> bool:
        """Enable public IP connection mode"""
        if self.port_manager.initialize_upnp():
            self.use_public_ip = True
            print("[+] Public IP mode enabled")
            return True
        else:
            print("[-] Failed to enable public IP mode (UPnP not available)")
            return False

    def disable_public_ip_mode(self):
        """Disable public IP mode and cleanup all forwards"""
        self.use_public_ip = False
        self.connection_tracker.cleanup_all()
        print("[+] Public IP mode disabled")

    def setup_listener(self, port: int) -> Tuple[Optional[str], Optional[int]]:
        """
        Setup listener with optional port forwarding

        Returns:
            Tuple of (address, port) - address is public IP if forwarded, else local IP
        """
        if self.use_public_ip:

            external_port = self.port_manager.add_port_forward(port)
            if external_port:
                public_ip = self.port_manager.get_external_ip()
                return (public_ip, external_port)
            else:
                print("[-] Port forwarding failed, falling back to local")
                return ("127.0.0.1", port)
        else:
            return ("127.0.0.1", port)

    def on_connection_established(self, connection_id: str, local_port: int):
        """Called when a connection is established"""
        if self.use_public_ip:
            self.connection_tracker.register_connection(connection_id, local_port)

    def on_connection_closed(self, connection_id: str):
        """Called when a connection is closed"""
        if self.use_public_ip:
            self.connection_tracker.unregister_connection(connection_id)

    def shutdown(self):
        """Shutdown and cleanup everything"""
        print("[+] Shutting down connection manager...")
        self.connection_tracker.cleanup_all()
        self.port_manager.remove_all_forwards()
