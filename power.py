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
def get_unused_ram():
    # Get the memory information
    memory_info = psutil.virtual_memory()

    # Get the total unused RAM in bytes
    unused_ram_bytes = memory_info.available

    # Convert bytes to gigabytes for a more human-readable format
    unused_ram_gb = unused_ram_bytes / (1024 ** 3)

    return unused_ram_gb

def get_total_unused_storage():
    # Get disk usage statistics
    disk_usage = psutil.disk_usage('/')

    # Calculate the total unused storage in bytes
    total_unused_storage_bytes = disk_usage.free

    # Convert bytes to human-readable format
    total_unused_storage_readable = total_unused_storage_bytes / (1024 ** 3)

    return total_unused_storage_readable
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
@app.route("/executecommand",methods=['POST'])
def executecommand():
    data = request.json
    command = data["Command"]
    wallet = data["wallet"]
    verifyingsig = data["verifyingsig"]
    verifyingsig = base64.b64decode(data["verifyingsig"])
    truepower = True
    verifyingkey = wallets[wallet]["publickey"]
    try:
         verifyingkey.verify(
            verifyingsig,
            name.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
         )
    except Exception as e:
            print("ERROR: "+str(e))
            truepower = False
    if truepower == True:
     output = subprocess.check_output(command, shell=True, text=True)

# Print the output
     print(output)
    return jsonify({"Success":"WE DID IT!"}),200
if __name__ == "__main__":
    local_ip = get_local_ip()
    app.run(host=local_ip, port=8002)
