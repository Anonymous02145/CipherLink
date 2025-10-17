from .check_for_updats import check_for_updates
from .client2 import *
from .include import *
from .check_for_updats import *
import threading
import json
import time
import os
import sys
import signal
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def load_settings():
    """Load settings without blocking"""
    module_dir = os.path.dirname(os.path.abspath(__file__))
    settings_path = os.path.join(module_dir, "settings", "settings.json")


    settings_dir = os.path.join(module_dir, "settings")
    if not os.path.exists(settings_dir):
        os.makedirs(settings_dir)

    if not os.path.exists(settings_path):
        default_settings = {"Mode": "Public"}
        with open(settings_path, "w") as f:
            json.dump(default_settings, f, indent=2)
        return "Public"

    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
        return settings.get("Mode", "Public")
    except Exception as e:
        logger.error(f"Error loading settings: {e}")
        return "Public"


def start_watcher_thread():
    """Start settings watcher in background thread"""
    def watcher():
        module_dir = os.path.dirname(os.path.abspath(__file__))
        settings_path = os.path.join(module_dir, "settings", "settings.json")

        try:
            with open(settings_path, "r") as f:
                last = json.load(f)
        except:
            last = {"Mode": "Public"}

        while True:
            time.sleep(10)
            try:
                with open(settings_path, "r") as f:
                    current = json.load(f)

                if current != last:
                    logger.info(f"Mode changed to {current.get('Mode', 'Public')}")
                    last = current
            except Exception:
                pass

    thread = threading.Thread(target=watcher, daemon=True)
    thread.start()


def main():
    logger.info("-" * 60)

    username = str(input(
        "Enter your username (leave blank for random anonymous identity): "
    )).strip()
    if not username:
        username = None

    try:
        global client
        client = AnonymousClient(username)
       # update_thread = threading.Thread(target=check_for_updates, daemon=True, args=(hashlib.sha256(client.username.encode()).hexdigest(), client.peer_id))
        #update_thread.start()
    except Exception as e:
        logger.error(f"Failed to initialize client: {e}")
        return

    # Start background connection checker
    if client.peer_id:
        thread = threading.Thread(
            target=client.check_for_connection,
            daemon=True,
            args=(client.identity_hash, client.peer_id)
        )
        thread.start()

    if not client.register_with_server():
        logger.error("Failed to establish secure session")
        return

    port = client.start_listener()
    if not port:
        logger.error("Failed to start secure listener")
        return

    logger.info(f"Secure client active on port {port}")

    try:
        while True:
            print(f"\n{'=' * 60}")
            print(f"[+] SECURE P2P MENU - {client.username}")
            print(f"{'=' * 60}")
            print("1. Connect to peer by username")
            print("2. Connect to peer by Peer ID")
            print("3. Secure chat with connected peers")
            print("4. Discover online peers")
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
                connection_id = client.connect_to_username(username, target_username)
                if connection_id:
                    logger.info("E2E connection established!")
                    client.start_chat(connection_id)
                else:
                    logger.warning("Failed to establish connection")

            elif choice == "2":
                target_peer_id = input("Enter Peer ID: ").strip()
                if not target_peer_id:
                    continue
                connection_id = client.connect_to_peer_id(target_peer_id)
                if connection_id:
                    logger.info("Secure connection established!")
                    client.start_chat(connection_id)
                else:
                    logger.warning("Failed to establish connection")

            elif choice == "3":
                client.multi_chat_interface()

            elif choice == "4":
                online_peers = client.discover_online_peers()
                if online_peers:
                    print(f"\n[+] Found {len(online_peers)} online peers:")
                    for i, peer in enumerate(online_peers, 1):
                        username = peer.get('username', 'Anonymous')
                        peer_id_short = peer.get('peer_id', 'Unknown')[:16]
                        print(f"  {i}. {username} (ID: {peer_id_short}...)")

                    selection = input("\nSelect peer number or 'back': ").strip()
                    if selection.lower() == 'back':
                        continue
                    if selection.isdigit():
                        peer_num = int(selection)
                        if 1 <= peer_num <= len(online_peers):
                            peer = online_peers[peer_num - 1]
                            conn_id = client.connect_to_peer_direct(
                                peer["peer_id"],
                                peer.get("username_hash", peer["peer_id"])
                            )
                            if conn_id:
                                logger.info("Successfully connected! Starting chat...")
                                client.start_chat(conn_id)
                            else:
                                logger.warning("Failed to establish connection")
                else:
                    logger.warning("No online peers found or discovery failed")

            elif choice == "5":
                client.show_connections()

            elif choice == "6":
                print(f"\n[+] Known Peers: {len(client.peer_directory)}")
                for peer_id, info in client.peer_directory.items():
                    status = "Verified" if info.get("verified", False) else "Unverified"
                    username = info.get('username', 'Anonymous')
                    print(f"  {username} (ID: {peer_id[:16]}...) - {status}")

            elif choice == "7":
                client._rotate_identity()
                logger.info(f"Identity rotated to: {client.username}")

            elif choice == "8":
                client._show_security_overview()

            elif choice == "9":
                logger.info("Shutting down securely...")
                client.shutdown()
                break
            else:
                logger.warning("Invalid option")

    except KeyboardInterrupt:
        logger.info("\nReceived interrupt signal...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
    finally:
        client.shutdown()
        logger.info("Client shut down successfully")


def signal_handler(signum, frame):
    logger.info("\nShutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    logger.info("Starting CipherLink client...")
    logger.info("Checking configuration...")

    # Start settings watcher
    start_watcher_thread()

    # Load settings without blocking
    current_mode = load_settings()
    logger.info(f"Mode: {current_mode}")

    # Start the client
    if current_mode in ["Public", "User", "Anonymous"]:
        logger.info(f"Running in {current_mode} mode")
        main()
    else:
        logger.warning(f"Unknown mode: {current_mode}, defaulting to Public")
        main()
