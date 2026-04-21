# E2EE Messaging Relay Prototype

[![Render API](https://img.shields.io/website?url=https%3A%2F%2Fe2ee-chat-jfml.onrender.com%2Fhealth&up_message=online&down_message=offline&label=render%20api)](https://e2ee-chat-jfml.onrender.com/health)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/backend-FastAPI-009688)
![PostgreSQL](https://img.shields.io/badge/database-PostgreSQL-336791)
![E2EE](https://img.shields.io/badge/messages-client--side%20E2EE-00aa55)

This is a student prototype of an end-to-end encrypted messaging system for a
whistleblower-to-journalist scenario. The important idea is that the server is
only a relay: it stores public keys, authentication data, metadata, and encrypted
message blobs, but it should never receive plaintext message content.


The project has two clients:

- `client.py` is the terminal client.
- `app.py` is the CustomTkinter desktop GUI client.

Both clients reuse the same Python cryptographic flow. The FastAPI server does
not encrypt or decrypt messages.

## How It Works

```text
Alice client                     Render/FastAPI relay                  Bob client
------------                     --------------------                  ----------
plaintext exists here
encrypt locally with
X25519 + HKDF + AES-GCM
        |
        | sends ciphertext only
        v
                               stores ciphertext in PostgreSQL
                               cannot decrypt message body
        |
        | Bob fetches ciphertext
        v
decrypt locally with
Bob's private key
plaintext appears here
```

The server can still see metadata such as usernames, sender, recipient,
timestamps, public keys, message IDs, and ciphertext. The message body is the
part protected by E2EE.

## Security Features

- X25519 key agreement between users.
- HKDF-SHA256 key derivation.
- AES-256-GCM authenticated encryption for message content.
- AES-GCM AAD binds `sender_id`, `recipient_id`, and `message_id`.
- Directional chain keys derive a fresh message key per message.
- Public-key fingerprints support out-of-band identity verification.
- The GUI remembers verified contact fingerprints in a local trust store.
- Local private keys are encrypted at rest with AES-256-GCM.
- Private-key encryption keys are derived with PBKDF2-HMAC-SHA256 and `600000`
  iterations.
- Server-side passwords are hashed with Argon2id.
- PostgreSQL stores persistent users and queued ciphertext messages.
- Messages expire 24 hours after first viewing.

Important limitation: this is a prototype, not full Signal Protocol. It has a
symmetric chain ratchet, but not a full DH ratchet with rotating ephemeral
ratchet keys.

## Project Files

- `server.py` - pure JSON FastAPI relay backed by PostgreSQL.
- `client.py` - terminal E2EE client.
- `app.py` - CustomTkinter GUI E2EE client.
- `evil_test.py` - tampering tests for AAD and AES-GCM integrity failure.
- `requirements.txt` - Python dependencies.
- `Procfile` - Render start command.

## Requirements

- Python 3.11 or newer.
- PostgreSQL database, local or hosted on Render/Railway.
- A working Tk installation if using the GUI.

On macOS with Homebrew Python, CustomTkinter may need Tk installed separately:

```bash
brew install python-tk@3.14
```

Use the version that matches your installed Python, for example
`python-tk@3.13` or `python-tk@3.14`.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Which Commands Do I Run?

Use this section if you just want copy-paste commands.

### Option A: GUI App With The Render Server

Use this for the easiest demo. You do not need to run `uvicorn` locally because
the server is already running on Render.

```bash
cd "/Users/aronbjartur/Downloads/e2ee project"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Then use the GUI:

1. Enter username and password.
2. Click `[REGISTER]` the first time.
3. Click `[LOGIN]` later.
4. Enter recipient and message.
5. Click `[SEND]`.
6. The recipient clicks `[REFRESH]`.

### Option B: Local Server Plus GUI App

Use this if you want the FastAPI server running on your own computer.

First, change the `SERVER_URL` line near the top of `app.py` to:

```python
SERVER_URL = e2ee.normalize_server_url("http://127.0.0.1:8000")
```

Terminal 1 starts the server:

```bash
cd "/Users/aronbjartur/Downloads/e2ee project"
source .venv/bin/activate
export DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE"
uvicorn server:app --host 127.0.0.1 --port 8000
```

Terminal 2 starts the GUI:

```bash
cd "/Users/aronbjartur/Downloads/e2ee project"
source .venv/bin/activate
python3 app.py
```

### Option C: Terminal Client With Render

Open one terminal for Alice:

```bash
cd "/Users/aronbjartur/Downloads/e2ee project"
source .venv/bin/activate
python3 client.py alice --server-url https://e2ee-chat-jfml.onrender.com --verbose
```

Open another terminal for Bob:

```bash
cd "/Users/aronbjartur/Downloads/e2ee project"
source .venv/bin/activate
python3 client.py bob --server-url https://e2ee-chat-jfml.onrender.com --verbose
```

There is no build or compile step required for normal use. If you want to check
that the Python files are valid before a demo, run:

```bash
python3 -m py_compile server.py client.py app.py evil_test.py
```

## Configure The Server

The server requires a PostgreSQL connection string:

```bash
export DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE"
```

Optional environment variables:

```bash
export APP_NAME="E2EE Messaging Relay"
export MESSAGE_RETENTION_HOURS="24"
export ARGON2_TIME_COST="3"
export ARGON2_MEMORY_COST="65536"
export ARGON2_PARALLELISM="4"
```

## Run The Server Locally

Start PostgreSQL first, then run:

```bash
source .venv/bin/activate
export DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/DATABASE"
uvicorn server:app --host 127.0.0.1 --port 8000 --reload
```

Check that the API is alive:

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Run The Terminal Client

Open one terminal for Alice:

```bash
source .venv/bin/activate
python3 client.py alice --server-url http://127.0.0.1:8000 --verbose
```

Open another terminal for Bob:

```bash
source .venv/bin/activate
python3 client.py bob --server-url http://127.0.0.1:8000 --verbose
```

The terminal menu gives three options:

```text
1. Send message
2. Check messages
3. Exit
```

Demo flow:

1. Start the server.
2. Start Alice with `python3 client.py alice --server-url http://127.0.0.1:8000 --verbose`.
3. Start Bob with `python3 client.py bob --server-url http://127.0.0.1:8000 --verbose`.
4. Alice chooses `1`, enters `bob`, and writes a message.
5. Alice verifies Bob's fingerprint.
6. Bob chooses `2` and receives the decrypted plaintext.
7. Use `--verbose` to show that the transmitted content is Base64 ciphertext.

For the deployed Render server, use:

```bash
python3 client.py alice --server-url https://e2ee-chat-jfml.onrender.com --verbose
python3 client.py bob --server-url https://e2ee-chat-jfml.onrender.com --verbose
```

## Run The GUI App

The GUI client is `app.py`.

```bash
source .venv/bin/activate
python3 app.py
```

The GUI currently points to:

```text
https://e2ee-chat-jfml.onrender.com
```

To change this, edit the `SERVER_URL` value near the top of `app.py`.

GUI demo flow:

1. Open the app.
2. Enter a username and password.
3. Click `[REGISTER]` the first time a user is created.
4. Click `[LOGIN]` for later sessions.
5. After login, show the `MY FINGERPRINT` section.
6. Enter a recipient and message.
7. Click `[SEND]`.
8. Verify the recipient fingerprint the first time, or if their key changes.
9. On the recipient app, click `[REFRESH]` to fetch and decrypt messages.

The GUI creates a temporary local lock file while a user is active, so the same
local identity cannot be opened twice at the same time on one machine.

## Render Deployment

The backend is a pure API. It does not serve HTML or a web UI.

Render uses the `Procfile`:

```text
web: uvicorn server:app --host 0.0.0.0 --port $PORT
```

Set this environment variable in Render:

```text
DATABASE_URL=postgresql://USER:PASSWORD@HOST:5432/DATABASE
```

The `/health` endpoint is used by the README badge:

```text
https://e2ee-chat-jfml.onrender.com/health
```

If the badge says `offline`, the Render service may be sleeping, restarting, or
misconfigured. Open the `/health` URL directly to wake/check it.

## API Summary

All protected endpoints use these headers:

```text
X-Auth-Username: alice
X-Auth-Password: password
```

Endpoints:

- `GET /health`
- `POST /register`
- `GET /public-key/{username}`
- `POST /send`
- `GET /messages/{username}`

Register body:

```json
{
  "username": "alice",
  "public_key": "base64-x25519-public-key",
  "password": "password"
}
```

Send body:

```json
{
  "message_id": "uuid",
  "sender": "alice",
  "recipient": "bob",
  "content": "base64 nonce + ciphertext + tag",
  "chain_index": 0
}
```

The `content` value is already encrypted before it reaches the server.

## What Is Stored Where

On the client:

- encrypted X25519 private key
- encrypted conversation chain state
- local trusted contact fingerprints
- temporary active-user lock files

On the server:

- usernames
- public keys
- Argon2id password hashes
- sender and recipient metadata
- timestamps
- Base64 ciphertext payloads

Not stored on the server:

- plaintext messages
- private keys
- message keys
- chain keys

## Message Lifecycle

- `queued_at` is set when ciphertext is submitted.
- `viewed_at` starts as `NULL`.
- The normal inbox endpoint returns only messages where `viewed_at` is still `NULL`.
- First recipient fetch sets `viewed_at` on those returned messages.
- `expires_at` becomes `viewed_at + 24 hours`.
- Viewed messages remain in PostgreSQL until expiry, but are not returned again.
- Expired messages are cleaned up by server endpoints.

## Evil Server / Tamper Test

Run this after the server is up and `DATABASE_URL` points to the same database:

```bash
source .venv/bin/activate
python3 evil_test.py
```

The test:

- creates test users
- sends encrypted messages
- directly modifies stored PostgreSQL ciphertext or metadata
- verifies that the recipient rejects tampered messages

This is the main automated proof that AES-GCM integrity and AAD binding work.

## Presentation Demo Checklist

- Show the Render health badge or open `/health`.
- Register Alice and Bob.
- Show each user's `MY FINGERPRINT`.
- Send a message from Alice to Bob.
- Show the server/database stores ciphertext, not plaintext.
- Refresh Bob and show successful plaintext decryption.
- Run `evil_test.py` to show tampering is rejected.
- Explain that Render is an untrusted relay, not the encryption endpoint.

## Honest Security Notes

This app works as an E2EE prototype for message content: plaintext is encrypted
on the sender client and decrypted on the recipient client. Render should only
see ciphertext.

It does not hide metadata, and it is not production-grade Signal. The biggest
remaining risks are endpoint compromise, users skipping fingerprint checks, and
the simplified ratchet design.
