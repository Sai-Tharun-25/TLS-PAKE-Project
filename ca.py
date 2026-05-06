from datetime import date

from crypto_utils import (
    b64e,
    canonical_json,
    generate_ed25519_private_key,
    public_key_to_b64,
    save_private_key,
    save_public_key,
    sign_message,
)
from storage import ensure_directories, save_json


CA_PRIVATE_PATH = "certs/ca_private.pem"
CA_PUBLIC_PATH = "certs/ca_public.pem"
SERVER_PRIVATE_PATH = "certs/server_private.pem"
SERVER_PUBLIC_PATH = "certs/server_public.pem"
SERVER_CERT_PATH = "certs/server_cert.json"


def main():
    ensure_directories()

    print("[CA] Generating CA signing key...")
    ca_private = generate_ed25519_private_key()
    ca_public = ca_private.public_key()

    print("[CA] Generating server signing key...")
    server_private = generate_ed25519_private_key()
    server_public = server_private.public_key()

    save_private_key(ca_private, CA_PRIVATE_PATH)
    save_public_key(ca_public, CA_PUBLIC_PATH)

    save_private_key(server_private, SERVER_PRIVATE_PATH)
    save_public_key(server_public, SERVER_PUBLIC_PATH)

    certificate_body = {
        "subject": "server.local",
        "issuer": "Demo CA",
        "server_public_key": public_key_to_b64(server_public),
        "valid_from": str(date.today()),
        "valid_to": "2026-12-31",
    }

    cert_signature = sign_message(ca_private, canonical_json(certificate_body))

    certificate = {
        "body": certificate_body,
        "signature": b64e(cert_signature),
    }

    save_json(SERVER_CERT_PATH, certificate)

    print("[CA] Generated CA key, server key, and signed server certificate.")
    print("[CA] Files saved in certs/.")


if __name__ == "__main__":
    main()