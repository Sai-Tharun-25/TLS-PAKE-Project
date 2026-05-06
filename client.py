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
    load_public_key,
    secure_random,
    sha256,
    verify_signature,
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
from setup import derive_password_verifier


CA_PUBLIC_PATH = "certs/ca_public.pem"


def transcript_hash(messages):
    joined = b"".join(canonical_json(m) for m in messages)
    return sha256(joined)


def verify_certificate(certificate, ca_public_key) -> bool:
    body = certificate["body"]
    signature = b64d(certificate["signature"])

    return verify_signature(
        ca_public_key,
        canonical_json(body),
        signature,
    )


def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python client.py <username> <password>")
        print()
        print("Example:")
        print("  python client.py alice password123")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    print("[Client] Loading CA public key...")

    try:
        ca_public_key = load_public_key(CA_PUBLIC_PATH)
    except FileNotFoundError:
        print("[Client] Missing CA public key.")
        print("[Client] Run first:")
        print("  python ca.py")
        sys.exit(1)

    # Generate client ephemeral X25519 key

    client_dh_private = generate_x25519_private_key()
    client_dh_public = client_dh_private.public_key()

    client_hello = {
        "type": "ClientHello",
        "username": username,
        "client_nonce": b64e(secure_random(32)),
        "client_x25519_public": x25519_public_to_b64(client_dh_public),
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        print(f"[Client] Connecting to {HOST}:{PORT}...")
        sock.connect((HOST, PORT))

        # Send ClientHello

        send_message(sock, client_hello)
        print("[Client] Sent ClientHello.")

        # Receive ServerHello

        server_hello = recv_message(sock)

        if server_hello.get("type") == "Error":
            print("[Client] Server error:", server_hello["message"])
            return

        if server_hello.get("type") != "ServerHello":
            raise ValueError("Expected ServerHello")

        print("[Client] Received ServerHello.")

        server_hello_body = {
            "type": server_hello["type"],
            "server_nonce": server_hello["server_nonce"],
            "server_x25519_public": server_hello["server_x25519_public"],
            "certificate": server_hello["certificate"],
            "pake_salt": server_hello["pake_salt"],
        }

        # Verify server certificate

        certificate = server_hello["certificate"]

        if not verify_certificate(certificate, ca_public_key):
            print("[Client] Certificate verification failed.")
            return

        print("[Client] Certificate verified.")

        # Verify server signature

        server_public_key_b64 = certificate["body"]["server_public_key"]
        server_public_key = ed25519_public_from_b64(server_public_key_b64)

        signature_input = canonical_json(client_hello) + canonical_json(server_hello_body)
        server_signature = b64d(server_hello["server_signature"])

        if not verify_signature(server_public_key, signature_input, server_signature):
            print("[Client] Server signature verification failed.")
            return

        print("[Client] Server signature verified.")

        # Compute shared secret

        server_dh_public = x25519_public_from_b64(server_hello["server_x25519_public"])
        dh_secret = x25519_shared_secret(client_dh_private, server_dh_public)

        salt = b64d(server_hello["pake_salt"])
        verifier = derive_password_verifier(username, password, salt)

        handshake_salt = transcript_hash([client_hello, server_hello_body])
        handshake_secret = hkdf_derive(
            secret=dh_secret + verifier,
            salt=handshake_salt,
            info=HANDSHAKE_SECRET_LABEL,
            length=32,
        )

        # Send ClientAuth

        auth_transcript = transcript_hash([client_hello, server_hello_body])
        client_authenticator = hmac_sha256(
            handshake_secret,
            CLIENT_AUTH_LABEL + auth_transcript,
        )

        client_auth = {
            "type": "ClientAuth",
            "client_authenticator": b64e(client_authenticator),
        }

        send_message(sock, client_auth)
        print("[Client] Sent ClientAuth.")

        # Receive ServerFinished

        server_finished = recv_message(sock)

        if server_finished.get("type") == "Error":
            print("[Client] Server error:", server_finished["message"])
            return

        if server_finished.get("type") != "ServerFinished":
            raise ValueError("Expected ServerFinished")

        finished_transcript = transcript_hash([client_hello, server_hello_body, client_auth])

        expected_server_finished = hmac_sha256(
            handshake_secret,
            SERVER_FINISHED_LABEL + finished_transcript,
        )

        received_server_finished = b64d(server_finished["server_finished"])

        if not hmac_compare(expected_server_finished, received_server_finished):
            print("[Client] ServerFinished verification failed.")
            return

        print("[Client] ServerFinished verified.")

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

        print("[Client] Secure channel established.")

        # Send encrypted application data

        message = "Hello secure server! This message is encrypted."

        encrypted_message = aesgcm_encrypt(
            client_app_key,
            message.encode("utf-8"),
            aad=AAD_CLIENT_TO_SERVER,
        )

        send_message(sock, {
            "type": "ApplicationData",
            "encrypted": encrypted_message,
        })

        print("[Client] Sent encrypted application message.")

        # Receive encrypted server response

        encrypted_response = recv_message(sock)

        if encrypted_response.get("type") != "ApplicationData":
            raise ValueError("Expected ApplicationData")

        response_plaintext = aesgcm_decrypt(
            server_app_key,
            encrypted_response["encrypted"],
            aad=AAD_SERVER_TO_CLIENT,
        )

        print("[Client] Decrypted server response:", response_plaintext.decode("utf-8"))


def hmac_compare(a: bytes, b: bytes) -> bool:
    import hmac
    return hmac.compare_digest(a, b)


if __name__ == "__main__":
    main()