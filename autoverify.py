from flask import Flask, request
import socket
app = Flask(__name__)
seedphrase = ""
import subprocess
import requests
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import time
from ast import If
from audioop import error
from http import server
from telnetlib import SE
from typing import Self
from unittest.util import _MAX_LENGTH
import requests
from bs4 import BeautifulSoup
import hashlib
import flask
from flask import Flask,request,jsonify
import time
import json
import ecdsa
from hashlib import sha256

import os
import psutil
import math
import socket
import pickle
import sys
import math
from flask import g
import sqlite3
import threading
import subprocess
import pyautogui
import speedtest
import copy
import sqlite3
import re
stuffindata = {}
def get_used_ram():
    # Get the memory information
    memory_info = psutil.virtual_memory()

    # Get the total used RAM in bytes
    used_ram_bytes = memory_info.used

    # Convert bytes to gigabytes for a more human-readable format
    used_ram_gb = used_ram_bytes / (1024 ** 3)

    return used_ram_gb
def get_total_used_storage():
    # Get disk usage statistics
    disk_usage = psutil.disk_usage('/')

    # Calculate the total used storage in bytes
    total_used_storage_bytes = disk_usage.used

    # Convert bytes to human-readable format
    total_used_storage_readable = psutil.bytes2human(total_used_storage_bytes)

    return  total_used_storage_readable
def remove_sql(input_string):
    # Regular expression pattern to match SQL keywords and common SQL syntax
    sql_pattern = r'\b(SELECT|UPDATE|INSERT|DELETE|DROP|CREATE|ALTER|TRUNCATE)\b|\-\-|;'

    # Remove SQL code using regex
    cleaned_string = re.sub(sql_pattern, '', input_string, flags=re.IGNORECASE)

    return cleaned_string


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
    decode_dss_signature
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from ecdsa import SigningKey,VerifyingKey
from ecdsa.curves import SECP256k1
import time
import pickle
import hashlib
import math
import socket
import requests
import base64
import copy
import random
import requests
from flask import app
from flask import request
from flask import Flask,jsonify
import mnemonic
import json
import base64
from mnemonic import Mnemonic
walletname = "Test"
seedphrase = "Test3"
seed_key = hashlib.sha256(seedphrase.encode()).digest()
mnemo = Mnemonic("english")
seed = mnemo.to_seed(seedphrase)
seed_key = hashlib.sha256(seedphrase.encode()).digest()
# Generate a private key

salt = "22".encode('utf-8')  
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
 )
key = kdf.derive(seedphrase.encode())

private_key3333 = ec.derive_private_key(
    int.from_bytes(key, byteorder='big'),  
    ec.SECP256R1(),  
    backend=default_backend()
)

private_pem = private_key3333.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_key3333333 = private_key3333.public_key()
public_pem = public_key3333333.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
data = {"walletname":walletname,"publickey":public_pem.decode('utf-8')}
requests.post("http://192.168.56.1:8002/createwallet",json=data)
signature = private_key3333.sign(
         "testythingy".encode("utf-8"),
         ec.ECDSA(hashes.SHA256())
)
verifyingsig = base64.b64encode(signature).decode('utf-8')
