from re import U
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
import uuid

URL_IP = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://checkip.amazonaws.com"]
BASE = "49.205.203.177"
URL_REGISTER ="https://ossie-grumous-nanci.ngrok-free.dev/register"
URL_AUTHENTICATE = "https://ossie-grumous-nanci.ngrok-free.dev/authenticate"
URL_GET_KEY = "https://ossie-grumous-nanci.ngrok-free.dev/get_key"
URL_SET_PORT = "https://ossie-grumous-nanci.ngrok-free.dev/set_listening_port"
URL_REQUEST_CONNECTION = "https://ossie-grumous-nanci.ngrok-free.dev/request_connection"
URL_DISCOVER_ONLINE = "https://ossie-grumous-nanci.ngrok-free.dev/discover_online"
URL_CHECK_FOR_CONNECTION = "https://ossie-grumous-nanci.ngrok-free.dev/check_for_connection"

MESSAGE_PADDING_SIZE = 256
SESSION_ROTATION_HOURS = 24
MAX_MESSAGE_SIZE = 1024 * 1024
HEARTBEAT_INTERVAL = 30
