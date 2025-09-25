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
TEST_IP = "127.0.0.1"
URL_BASE = "http://127.0.0.1:8000"
URL_REGISTER = f"{URL_BASE}/register"
URL_AUTHENTICATE = f"{URL_BASE}/authenticate"
URL_GET_KEY = f"{URL_BASE}/get_key"
URL_SET_PORT = f"{URL_BASE}/set_listening_port"
URL_REQUEST_CONNECTION = f"{URL_BASE}/request_connection"
URL_DISCOVER_ONLINE = f"{URL_BASE}/discover_online"

MESSAGE_PADDING_SIZE = 256
SESSION_ROTATION_HOURS = 24
MAX_MESSAGE_SIZE = 1024 * 1024
HEARTBEAT_INTERVAL = 30