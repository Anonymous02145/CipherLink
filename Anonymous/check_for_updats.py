import requests

URL_CHECK_UPDATE = "127.0.0.1:8080/check_update"

def check_for_updates(username_hash, peer_id):

    with open("Version.txt", "r") as _file:
        current_version = _file.read().strip()

    payload = {
        "User_Hash": username_hash,
        "Peer_ID": peer_id,
        "App_Version": current_version
    }
    _current = requests.get(URL_CHECK_UPDATE, params=payload, timeout=5)
