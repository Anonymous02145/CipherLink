import requests
import os

URL_CHECK_UPDATE = "https://ossie-grumous-nanci.ngrok-free.dev/check_update"
os.system("touch /home/fsociety/CipherLink/Anonymous/Version.txt")
os.system("echo 'version 0.1' > Version.txt")

def check_for_updates(username_hash : str, peer_id : str):

    while(True):

        try:

            with open("Version.txt", "r") as _file:
                current_version = _file.read().strip()

            payload = {
            		"User_Hash": username_hash,
            		"Peer_ID": peer_id,
            		"App_Version": current_version
        		}
            _current = requests.get(URL_CHECK_UPDATE, params=payload, timeout=5)

        except Exception as e:

            print(e)
