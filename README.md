# TLS-PAKE-Project

## Project Description
This project implements a simplified TLS 1.3-style handshake with password-based client authentication.

The server is authenticated using a CA-signed certificate and digital signature.  
The client is authenticated using a password-derived verifier.  
After authentication, both sides derive application keys using HKDF and exchange encrypted messages using AES-GCM.

## Requirements
- Python 3.10 or newer
- `cryptography` library

Install dependencies:

```
pip install -r requirements.txt
```

## Files

- `ca.py` - generates CA keys, server keys, and server certificate
- `setup.py` - registers a username and password
- `server.py` - runs the server
- `client.py` - runs the client
- `crypto_utils.py` - cryptographic helper functions
- `messages.py` - socket message send/receive helpers
- `storage.py` - JSON storage helpers
- `protocol.py` - protocol constants

## How to Run

### 1. Generate keys and certificate

```
python ca.py
```

### 2. Register a user

```
python setup.py register sai itsme
```

### 3. Start the server

```
python server.py
```

### 4. Run the client in another terminal

```
python client.py sai itsme
```

## Wrong Password Test

Restart the server, then run:

```
python client.py sai wrongpassword
```

The server should reject the client authentication.

## Expected Result

With the correct password, the client verifies the server certificate, verifies the server signature, establishes a secure channel, sends an encrypted message, and decrypts the server response.

With the wrong password, the server rejects the client.