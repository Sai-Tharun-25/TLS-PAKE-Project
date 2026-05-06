import socket
import sys

from crypto_utils import (
    aesgcm_decrypt,
    aesgcm_encrypt,
    b64d,
    b64e,
    canonical_json,
    ed25519_public_from_b64,
    generate_x25519_private_key,
    hkdf_derive,
    hmac_sha256,
    load_private_key,
    secure_random,
    sha256,
    sign_message,
    x25519_public_from_b64,
    x25519_public_to_b64,
    x25519_shared_secret,
)
from messages import recv_message, send_message
from protocol import (
    AAD_CLIENT_TO_SERVER,
    AAD_SERVER_TO_CLIENT,
    CLIENT_APP_KEY_LABEL,
    CLIENT_AUTH_LABEL,
    HANDSHAKE_SECRET_LABEL,
    HOST,
    PORT,
    SERVER_APP_KEY_LABEL,
    SERVER_FINISHED_LABEL,
)
from storage import load_json


SERVER_PRIVATE_PATH = "certs/server_private.pem"
SERVER_CERT_PATH = "certs/server_cert.json"
PASSWORD_DB_PATH = "data/password_db.json"


def transcript_hash(messages):
    joined = b"".join(canonical_json(m) for m in messages)
    return sha256(joined)


def main():
    print("[Server] Loading server private key, certificate, and password database...")

    try:
        server_signing_private = load_private_key(SERVER_PRIVATE_PATH)
        server_cert = load_json(SERVER_CERT_PATH)
        password_db = load_json(PASSWORD_DB_PATH)
    except FileNotFoundError as e:
        print("[Server] Missing file:", e)
        print("[Server] Run these first:")
        print("  python ca.py")
        print("  python setup.py register alice password123")
        sys.exit(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)

        print(f"[Server] Listening on {HOST}:{PORT}")

        conn, addr = server_sock.accept()

        with conn:
            print(f"[Server] Client connected from {addr}")

            # Receive ClientHello
            client_hello = recv_message(conn)

            if client_hello.get("type") != "ClientHello":
                raise ValueError("Expected ClientHello")

            username = client_hello["username"]

            if username not in password_db:
                print("[Server] Unknown username.")
                send_message(conn, {
                    "type": "Error",
                    "message": "Unknown username"
                })
                return

            print(f"[Server] Received ClientHello for username: {username}")

            user_record = password_db[username]
            salt_b64 = user_record["salt"]
            verifier = b64d(user_record["verifier"])

            # Generate ephemeral X25519 key
            server_dh_private = generate_x25519_private_key()
            server_dh_public = server_dh_private.public_key()

            server_hello_body = {
                "type": "ServerHello",
                "server_nonce": b64e(secure_random(32)),
                "server_x25519_public": x25519_public_to_b64(server_dh_public),
                "certificate": server_cert,
                "pake_salt": salt_b64,
            }

            # Server signs the transcript so far.
            signature_input = canonical_json(client_hello) + canonical_json(server_hello_body)
            server_signature = sign_message(server_signing_private, signature_input)

            server_hello = dict(server_hello_body)
            server_hello["server_signature"] = b64e(server_signature)

            send_message(conn, server_hello)
            print("[Server] Sent ServerHello, certificate, and signature.")

            # Compute shared secret
            client_dh_public = x25519_public_from_b64(client_hello["client_x25519_public"])
            dh_secret = x25519_shared_secret(server_dh_private, client_dh_public)

            handshake_salt = transcript_hash([client_hello, server_hello_body])
            handshake_secret = hkdf_derive(
                secret=dh_secret + verifier,
                salt=handshake_salt,
                info=HANDSHAKE_SECRET_LABEL,
                length=32,
            )

            # Receive ClientAuth
            client_auth = recv_message(conn)

            if client_auth.get("type") != "ClientAuth":
                raise ValueError("Expected ClientAuth")

            auth_transcript = transcript_hash([client_hello, server_hello_body])
            expected_client_authenticator = hmac_sha256(
                handshake_secret,
                CLIENT_AUTH_LABEL + auth_transcript,
            )

            received_client_authenticator = b64d(client_auth["client_authenticator"])

            if not hmac_compare(expected_client_authenticator, received_client_authenticator):
                print("[Server] Client authentication failed.")
                send_message(conn, {
                    "type": "Error",
                    "message": "Client authentication failed"
                })
                return

            print("[Server] Client authenticated successfully.")

            # Send ServerFinished
            finished_transcript = transcript_hash([client_hello, server_hello_body, client_auth])
            server_finished_mac = hmac_sha256(
                handshake_secret,
                SERVER_FINISHED_LABEL + finished_transcript,
            )

            server_finished = {
                "type": "ServerFinished",
                "server_finished": b64e(server_finished_mac),
            }

            send_message(conn, server_finished)
            print("[Server] Sent ServerFinished.")

            # Derive application keys
            final_transcript = transcript_hash([
                client_hello,
                server_hello_body,
                client_auth,
                server_finished,
            ])

            client_app_key = hkdf_derive(
                handshake_secret,
                salt=final_transcript,
                info=CLIENT_APP_KEY_LABEL,
                length=32,
            )

            server_app_key = hkdf_derive(
                handshake_secret,
                salt=final_transcript,
                info=SERVER_APP_KEY_LABEL,
                length=32,
            )

            print("[Server] Secure channel established.")

            # Receive encrypted message
            encrypted_from_client = recv_message(conn)

            if encrypted_from_client.get("type") != "ApplicationData":
                raise ValueError("Expected ApplicationData")

            plaintext = aesgcm_decrypt(
                client_app_key,
                encrypted_from_client["encrypted"],
                aad=AAD_CLIENT_TO_SERVER,
            )

            print("[Server] Decrypted client message:", plaintext.decode("utf-8"))

            # Send encrypted response
            response_text = "Hello client, your secure message was received."
            encrypted_response = aesgcm_encrypt(
                server_app_key,
                response_text.encode("utf-8"),
                aad=AAD_SERVER_TO_CLIENT,
            )

            send_message(conn, {
                "type": "ApplicationData",
                "encrypted": encrypted_response,
            })

            print("[Server] Sent encrypted response.")


def hmac_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison wrapper.
    """
    import hmac
    return hmac.compare_digest(a, b)


if __name__ == "__main__":
    main()