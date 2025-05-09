import os
import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit

# Configurable Trusted Key ID Prefix (First 8 characters of subscription key_id)
EXPECTED_KEY_ID_PREFIX = "ee831110"

# PEM Public Key as provided in subscription response
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2J2jxaXO7f3ePAxvWSeGXx4MUqnxQQpsXLDWdLZV/8i0IRwz3zpDLrLQ4UQ4FAzg/ccLFBIfsfmc7aweJwFdQg==
-----END PUBLIC KEY-----"""

def verify_lucid_signature(header_value, body):
    try:
        parts = header_value.strip().split(',')
        if len(parts) < 2:
            print("❌ Invalid header format")
            return False

        timestamp = parts[0].split(':')[1]
        schema_version, key_id, signature_b64 = parts[1].split(':')

        # Validate Key ID Prefix
        if key_id != EXPECTED_KEY_ID_PREFIX:
            print(f"❌ Key ID mismatch. Expected {EXPECTED_KEY_ID_PREFIX}, got {key_id}")
            return False

        # Construct the message to verify
        message = f"{timestamp}.{body}"

        # Decode the base64 signature
        signature_bytes = base64.b64decode(signature_b64)

        # Load the public key
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode())

        # Perform the signature verification
        public_key.verify(signature_bytes, message.encode(), ec.ECDSA(hashes.SHA256()))
        return True

    except InvalidSignature:
        print("❌ Signature verification failed.")
        return False
    except Exception as e:
        print(f"❌ Verification error: {e}")
        return False

@app.route("/webhook", methods=["POST"])
def webhook():
    print("✅ Received request at /webhook")

    body = request.data.decode()
    # print("🔍 Body:", body)

    signature_header = request.headers.get('X-Lucid-Signature')
    if not signature_header:
        print("❌ Missing X-Lucid-Signature header")
        return jsonify({"error": "Missing X-Lucid-Signature header"}), 400

    if verify_lucid_signature(signature_header, body):
        print("✅ Signature Verified Successfully")
        return jsonify({"status": "signature valid"}), 200
    else:
        print("❌ Signature invalid or verification failed")
        return jsonify({"error": "Invalid signature"}), 401

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(port=port, host="0.0.0.0")