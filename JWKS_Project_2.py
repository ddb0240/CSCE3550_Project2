from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "127.0.0.1"
serverPort = 8080
# Database definition
def create_db():
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys(
                            kid INTEGER PRIMARY KEY AUTOINCREMENT,
                            key TEXT NOT NULL,
                            exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()

# Add private key function
def add_key_to_db(key_data, exp):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    c.execute("INSERT INTO keys (key, exp) VALUES (?, ?)",
              (key_data, exp))
    conn.commit()
    conn.close()

# Return private key function
def get_private_key_from_db(kid):
    conn = sqlite3.connect('totally_not_my_privateKeys.db')
    c = conn.cursor()
    c.execute("SELECT key FROM keys WHERE kid = ?", (kid, ))
    row = c.fetchone()
    conn.close()
    if row:
        return row[0]
    return None
# Converts key into a PEM
def serialize_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode('utf-8')
# Converts an integer value into a Base64 encoded string
def int_to_base64(value):
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    # HTTP requests
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return
    # /auth endpoint for private key
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            headers = {"kid": "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(
                    hours=1)

            pem = get_private_key_from_db(headers["kid"])
            if pem:
                encoded_jwt = jwt.encode(token_payload,
                                         pem,
                                         algorithm="RS256",
                                         headers=headers)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(encoded_jwt, "utf-8"))
                return
            else:
                self.send_response(404)
                self.end_headers()
                return

        self.send_response(405)
        self.end_headers()
        return
    # /.well-known/jwks.json endpoint for displaying keys
    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            conn = sqlite3.connect('totally_not_my_privateKeys.db')
            c = conn.cursor()
            c.execute("SELECT kid, key FROM keys")
            rows = c.fetchall()
            conn.close()

            keys = {
                "keys": [{
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": row[0],
                    "n": int_to_base64(numbers.public_numbers.n),
                    "e": int_to_base64(numbers.public_numbers.e),
                } for row in rows]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    # Create database
    create_db()
    # Create valid and expired keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    serialized_private_key = serialize_private_key(private_key)
    expired_serialized_private_key = serialize_private_key(expired_key)

    add_key_to_db(serialized_private_key, datetime.datetime.utcnow() + datetime.timedelta(hours=1))
    add_key_to_db(expired_serialized_private_key, datetime.datetime.utcnow() - datetime.timedelta(hours=1))

    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
