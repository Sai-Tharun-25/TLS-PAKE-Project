import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))

def canonical_json(obj: Dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def secure_random(length: int = 32) -> bytes:
    return os.urandom(length)

def generate_ed25519_private_key():
    return ed25519.Ed25519PrivateKey.generate()

def save_private_key(private_key, path: str):
    data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(data)

def save_public_key(public_key, path: str):
    data = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(data)

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def public_key_to_b64(public_key) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)

def ed25519_public_from_b64(data: str):
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(data))

def sign_message(private_key, message: bytes) -> bytes:
    return private_key.sign(message)

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False

def generate_x25519_private_key():
    return x25519.X25519PrivateKey.generate()

def x25519_public_to_b64(public_key) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)

def x25519_public_from_b64(data: str):
    return x25519.X25519PublicKey.from_public_bytes(b64d(data))

def x25519_shared_secret(private_key, peer_public_key) -> bytes:
    return private_key.exchange(peer_public_key)

def hkdf_derive(secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(secret)

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }

def aesgcm_decrypt(key: bytes, encrypted_obj: Dict[str, str], aad: bytes = b"") -> bytes:
    nonce = b64d(encrypted_obj["nonce"])
    ciphertext = b64d(encrypted_obj["ciphertext"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)