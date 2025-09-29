from .client import AnonymousClient
from .include import *
import json
import time
import os
import sys
import signal

def load_settings():
    """Load settings without blocking"""
    module_dir = os.path.dirname(os.path.abspath(__file__))
    settings_path = os.path.join(module_dir, "settings", "settings.json")

    # Create settings directory and default file if they don't exist
    settings_dir = os.path.join(module_dir, "settings")
    if not os.path.exists(settings_dir):
        os.makedirs(settings_dir)

    if not os.path.exists(settings_path):
        default_settings = {"Status": "Public"}
        with open(settings_path, "w") as f:
            json.dump(default_settings, f, indent=2)
        return "Public"

    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
        return settings.get("Status", "Public")
    except Exception as e:
        print(f"[-] Error loading settings: {e}")
        return "Public"


def start_watcher_thread():
    """Start settings watcher in background thread (for future use)"""
    def watcher():
        module_dir = os.path.dirname(os.path.abspath(__file__))
        settings_path = os.path.join(module_dir, "settings", "settings.json")

        try:
            with open(settings_path, "r") as f:
                last = json.load(f)
        except:
            last = {"Status": "Public"}

        while True:
            time.sleep(10)
            try:
                with open(settings_path, "r") as f:
                    current = json.load(f)

                if current != last:
                    print(f"[*] Mode changed to {current.get('Status', 'Public')}")
                    last = current
                    # TODO: Notify UI or trigger mode change
            except Exception:
                pass

    import threading
    thread = threading.Thread(target=watcher, daemon=True)
    thread.start()


def main():
    print("-" * 60)

    username = input(
        "Enter your username (leave blank for random anonymous identity): "
    ).strip()
    if not username:
        username = None

    client = AnonymousClient(username)

    if not client.register_with_server():
        print("[-] Failed to establish secure session")
        return

    port = client.start_listener()
    if not port:
        print("[-] Failed to start secure listener")
        return

    client.print_status_line(f"[+] Secure client active on port {port}")

    try:
        while True:
            print(f"\n{'=' * 60}")
            print(f"[+] SECURE P2P MENU - {client.username}")
            print(f"{'=' * 60}")
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
                    continue
                connection_id = client.connect_to_username(target_username)
                if connection_id:
                    print(f"[+] E2E connection established!")
                    client.start_chat(connection_id)

            elif choice == "2":
                target_peer_id = input("Enter Peer ID: ").strip()
                if not target_peer_id:
                    continue
                connection_id = client.connect_to_peer_id(target_peer_id)
                if connection_id:
                    print(f"[+] Secure connection established!")
                    client.start_chat(connection_id)

            elif choice == "3":
                client.multi_chat_interface()

            elif choice == "4":
                print("[+] Discovering secure peers...")
                online_peers = client.discover_online_peers()
                if online_peers:
                    print(f"\n[+] Found {len(online_peers)} online peers")
                    for i, peer in enumerate(online_peers, 1):
                        print(
                            f"  {i}. User_{peer['peer_id'][:8]} (ID: {peer['peer_id'][:16]}...)"
                        )

                    selection = input("\nSelect peer number or 'back': ").strip()
                    if selection.lower() != "back":
                        try:
                            peer_num = int(selection)
                            if 1 <= peer_num <= len(online_peers):
                                peer = online_peers[peer_num - 1]
                                connection_id = client.connect_to_peer_direct(
                                    peer["peer_id"], peer["username_hash"]
                                )
                                if connection_id:
                                    client.start_chat(connection_id)
                        except ValueError:
                            pass

            elif choice == "5":
                client.show_connections()

            elif choice == "6":
                print(f"\n[+] Known Peers: {len(client.peer_directory)}")
                for peer_id, info in client.peer_directory.items():
                    status = "Verified" if info["verified"] else "Unverified"
                    print(f"  {info['username']} (ID: {peer_id[:16]}...) - {status}")

            elif choice == "7":
                client._rotate_identity()
                print(f"[+] Identity rotated to: {client.username}")

            elif choice == "8":
                client._show_security_overview()

            elif choice == "9":
                client.shutdown()
                break

    except KeyboardInterrupt:
        pass
    except Exception:
        pass
    finally:
        client.shutdown()


def signal_handler(signum, frame):
    print("\n[+] Shutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("[+] Starting CipherLink client...")
    print("[+] Checking configuration...")

    # Load settings without blocking
    current_mode = load_settings()
    print(f"[+] Mode: {current_mode}")

    # Start background watcher (optional)
    # start_watcher_thread()

    # Start the client
    if current_mode == "Public":
        print("[+] Running in Public mode")
        main()
    elif current_mode == "User":
        print("[!] User mode not yet implemented")
    elif current_mode == "Anonymous":
        print("[!] Anonymous mode not yet implemented")
    else:
        print(f"[-] Unknown mode: {current_mode}, defaulting to Public")
        main()
