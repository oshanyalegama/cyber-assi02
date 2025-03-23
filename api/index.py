from flask import Flask, request, jsonify
import base64
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
keys = {}  # Dictionary to store keys with their IDs

VALID_AES_KEY_SIZES = {128, 192, 256}

def generate_aes_key(key_size):
    if key_size not in VALID_AES_KEY_SIZES:
        return None
    key = os.urandom(key_size // 8)
    return base64.b64encode(key).decode()

def generate_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(private_pem).decode(), base64.b64encode(public_pem).decode()

@app.route('/')
def home():
  return '<h1>This is an API used for cryptography developed by Team Encryptos</h1>'

@app.route("/generate-key", methods=["POST"])
def generate_key():
    data = request.json
    key_type = data.get("key_type")
    key_size = data.get("key_size", 256)
    key_id = str(len(keys) + 1)
    
    if key_type == "AES":
        key_value = generate_aes_key(key_size)
    elif key_type == "RSA":
        private_key, public_key = generate_rsa_key()
        keys[key_id] = {"private": private_key, "public": public_key}
        return jsonify({"key_id": key_id, "public_key": public_key})
    else:
        return jsonify({"error": "Unsupported key type"}), 400
    
    keys[key_id] = key_value
    return jsonify({"key_id": key_id, "key_value": key_value})

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json
    key_id = data.get("key_id")
    plaintext = data.get("plaintext").encode()
    algorithm = data.get("algorithm")
    
    if key_id not in keys:
        return jsonify({"error": "Invalid key_id"}), 400
    
    if algorithm == "AES":
        key = base64.b64decode(keys[key_id])
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_plaintext = plaintext.ljust((len(plaintext) + 15) // 16 * 16)
        ciphertext = iv + encryptor.update(padded_plaintext) + encryptor.finalize()
        return jsonify({"ciphertext": base64.b64encode(ciphertext).decode()})
    
    elif algorithm == "RSA":
        public_key_pem = base64.b64decode(keys[key_id]["public"])
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({"ciphertext": base64.b64encode(ciphertext).decode()})
    
    return jsonify({"error": "Unsupported algorithm"}), 400

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.json
    key_id = data.get("key_id")
    ciphertext = base64.b64decode(data.get("ciphertext"))
    algorithm = data.get("algorithm")
    
    if key_id not in keys:
        return jsonify({"error": "Invalid key_id"}), 400
    
    if algorithm == "AES":
        key = base64.b64decode(keys[key_id])
        iv, ciphertext = ciphertext[:16], ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return jsonify({"plaintext": plaintext.strip().decode()})
    
    elif algorithm == "RSA":
        private_key_pem = base64.b64decode(keys[key_id]["private"])
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({"plaintext": plaintext.decode()})
    
    return jsonify({"error": "Unsupported algorithm"}), 400

@app.route("/generate-hash", methods=["POST"])
def generate_hash():
    data = request.json
    input_data = data.get("data").encode()
    algorithm = data.get("algorithm", "SHA-256")
    
    if algorithm == "SHA-256":
        hash_value = hashlib.sha256(input_data).digest()
    elif algorithm == "SHA-512":
        hash_value = hashlib.sha512(input_data).digest()
    else:
        return jsonify({"error": "Unsupported hashing algorithm"}), 400
    
    return jsonify({"hash_value": base64.b64encode(hash_value).decode(), "algorithm": algorithm})

@app.route("/verify-hash", methods=["POST"])
def verify_hash():
    data = request.json
    input_data = data.get("data").encode()
    hash_value = base64.b64decode(data.get("hash_value"))
    algorithm = data.get("algorithm", "SHA-256")
    
    if algorithm == "SHA-256":
        computed_hash = hashlib.sha256(input_data).digest()
    elif algorithm == "SHA-512":
        computed_hash = hashlib.sha512(input_data).digest()
    else:
        return jsonify({"error": "Unsupported hashing algorithm"}), 400
    
    is_valid = computed_hash == hash_value
    return jsonify({"is_valid": is_valid, "message": "Hash matches the data." if is_valid else "Hash does not match."})

if __name__ == "__main__":
    app.run(debug=True)
