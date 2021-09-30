"""
Cookiemonsta is a Python3 script for Windows to decrypt Google Chrome's cookies and output to JSON.

To run:
python cookiemonsta.py [optional domain filter]

Example:
python cookiemonsta.py google

"""
import os
import json
import base64
import sqlite3
import sys
from datetime import datetime, timezone
from Crypto.Cipher import AES
import win32crypt


LOCALSTATE = r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State'
COOKIES = r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies'
QUERY = 'SELECT host_key, name, value, expires_utc, encrypted_value FROM cookies'

def get_epoch():
    """Gets timestamp of Windows epoch."""
    return datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp()

def get_current_time():
    """Gets the current time in Chrome's format to evaluate against expiration date."""
    return int(round((datetime.now(timezone.utc).timestamp() - get_epoch()) * 1000000))

def get_connection():
    """Connects to Cookies db and query cookies."""
    cookies_path = os.path.expandvars(COOKIES)
    connection = sqlite3.connect(cookies_path)
    connection.text_factory = bytearray
    return connection

def get_key():
    """Reads Chrome's encrypted key and decrypts using DPAPI."""
    encrypted_key = ""
    state_path = os.path.expandvars(LOCALSTATE)
    # Read encrypted key from Chrom's local state file
    with open(state_path, 'r', encoding='UTF-8') as file:
        state = json.load(file)
        encrypted_key = state['os_crypt']['encrypted_key']
    key_bytes = base64.b64decode(encrypted_key)[5:]
    return win32crypt.CryptUnprotectData(key_bytes, None, None, None, 0)[1]

def decrypt_cookie_value(value, key):
    """Decrypts cookie."""
    nonce = value[3:3+12]
    ciphertext = value[3+12:-16]
    tag = value[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def jsonify(cookie_name, cookie_value, domain, expires):
    """Returns json of cookie data, decoded to str."""
    data = {}
    data['name'] = cookie_name.decode()
    data['value'] = cookie_value.decode()
    data['domain'] = domain.decode()
    data['expires'] = expires
    return json.dumps(data)

if __name__ == "__main__":
    DOMAIN_FILTER = ""
    if len(sys.argv) > 1:
        DOMAIN_FILTER = sys.argv[1]
    decryption_key = get_key()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(QUERY)
    current_time = get_current_time()

    # Decrypt all cookie values in database
    for host_key, value, name, expires_utc, encrypted_value in cursor.fetchall():
        if expires_utc - current_time > 0:	# Fresh cookies only
            if encrypted_value[:3] == b'v10':	# v10 signifies cookie was encrypted with DPAPI
                if DOMAIN_FILTER and DOMAIN_FILTER in host_key.decode():  # Filter by domain
                    decrypted_value = decrypt_cookie_value(encrypted_value, decryption_key)
                    print(jsonify(name,decrypted_value,host_key,expires_utc))
                elif not DOMAIN_FILTER:    # If  no filter is suppled, decrypt ALL the cookies
                    decrypted_value = decrypt_cookie_value(encrypted_value, decryption_key)
                    print(jsonify(name,decrypted_value,host_key,expires_utc))
            else:
                print("Cannot decrypt " + name.decode() + ": not a v10 cookie")
    conn.close()
