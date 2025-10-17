import requests
import socket
import ipaddress

class Compare:
    def get_local_ip(self):
        local_ip = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
        except socket.error:
            return None
        finally:
            sock.close()

        return local_ip

    def get_public_ip(self):
        try:
            response = requests.get('https://api.ipify.org')
            return response.text
        except requests.RequestException:
            return None

    def compare_ips(self, local_ip, public_ip):
        try:
            local_ip = ipaddress.ip_address(local_ip)
            public_ip = ipaddress.ip_address(public_ip)
            if ipaddress.IPv4Address(local_ip).is_private:
                    print("Local IP is a private address (likely behind NAT).")
                    return True

            if local_ip == public_ip:
                    print("Local IP matches public IP (likely not behind NAT).")
                    return False
            else:
                    print("Local IP does not match public IP (behind NAT).")
                    return True
        except ValueError:
            return False
