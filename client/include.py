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
URL_REGISTER = "https://lz1np6nl-8000.inc1.devtunnels.ms/register"
URL_AUTHENTICATE = "https://lz1np6nl-8000.inc1.devtunnels.ms/authenticate"
URL_GET_KEY = "https://lz1np6nl-8000.inc1.devtunnels.ms/get_key"
URL_SET_PORT = "https://lz1np6nl-8000.inc1.devtunnels.ms/set_listening_port"
URL_REQUEST_CONNECTION = "https://lz1np6nl-8000.inc1.devtunnels.ms/request_connection"
URL_DISCOVER_ONLINE = "https://lz1np6nl-8000.inc1.devtunnels.ms/discover_online"
URL_CHECK_FOR_CONNECTION = "https://lz1np6nl-8000.inc1.devtunnels.ms/check_for_connection"

MESSAGE_PADDING_SIZE = 256
SESSION_ROTATION_HOURS = 24
MAX_MESSAGE_SIZE = 1024 * 1024
HEARTBEAT_INTERVAL = 30
