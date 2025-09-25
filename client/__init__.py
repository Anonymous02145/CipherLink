from client import AnonymousClient
from include import *
import json
import time

def watcher():
    with open("settings/settings.json", "r") as _file:
        _last = json.load(_file)
        
        
    while True:
        time.sleep(10)
        try:
            with open("settings/settings.json", "r") as _file:
                _current = json.load(_file)
            
            if _current != _last:
                print("File has been changed")
                break
            
        except FileExistsError as f:
            print(f)
            break
        
        except FileNotFoundError as _f:
            print("Settings Not found")
            break

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
        
if __name__ == "__main__":
    
    def signal_handler(signum, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    main()

