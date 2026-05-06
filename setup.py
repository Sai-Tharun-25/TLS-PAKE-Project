import sys

from crypto_utils import b64e, hkdf_derive, secure_random
from storage import ensure_directories, load_json_or_empty, save_json


PASSWORD_DB_PATH = "data/password_db.json"


def derive_password_verifier(username: str, password: str, salt: bytes) -> bytes:
    password_bytes = password.encode("utf-8")
    info = b"pake password verifier:" + username.encode("utf-8")
    return hkdf_derive(password_bytes, salt=salt, info=info, length=32)


def register_user(username: str, password: str):
    ensure_directories()

    db = load_json_or_empty(PASSWORD_DB_PATH)

    salt = secure_random(16)
    verifier = derive_password_verifier(username, password, salt)

    db[username] = {
        "salt": b64e(salt),
        "verifier": b64e(verifier),
    }

    save_json(PASSWORD_DB_PATH, db)

    print(f"[Setup] Registered user: {username}")
    print("[Setup] Password database updated at data/password_db.json")
    print("[Setup] Plaintext password was not stored.")


def main():
    if len(sys.argv) != 4 or sys.argv[1] != "register":
        print("Usage:")
        print("  python setup.py register <username> <password>")
        sys.exit(1)

    username = sys.argv[2]
    password = sys.argv[3]

    register_user(username, password)


if __name__ == "__main__":
    main()