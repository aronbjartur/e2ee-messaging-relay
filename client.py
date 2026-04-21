from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import getpass
import json
import os
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

import requests
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def normalize_server_url(server_url: str) -> str:
    normalized = server_url.strip().rstrip("/")
    if not normalized:
        raise ValueError("Server URL cannot be blank.")
    return normalized


SERVER_URL = normalize_server_url(
    os.getenv("E2EE_SERVER_URL", os.getenv("SERVER_URL", "http://127.0.0.1:8000"))
)
REQUEST_TIMEOUT_SECONDS = 5
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
SYMMETRIC_KEY_SIZE = 32
KEY_DIRECTORY = Path(__file__).resolve().parent / "keys"
MESSAGE_MAX_AGE = timedelta(hours=24)
PRIVATE_KEY_ENCRYPTION_SALT_SIZE = 16
PRIVATE_KEY_ENCRYPTION_ITERATIONS = 600_000
PRIVATE_KEY_FILE_VERSION = 1
ROOT_KEY_INFO_PREFIX = b"root-key:"
CHAIN_KEY_INFO_PREFIX = b"chain-key:"
CHAIN_STEP_INFO = b"chain-step"


@dataclass
class ConversationState:
    send_chain_key: bytearray
    send_index: int = 0
    receive_chain_key: bytearray = field(default_factory=bytearray)
    receive_index: int = 0


@dataclass
class ClientIdentity:
    username: str
    private_key: X25519PrivateKey
    public_key_b64: str
    private_key_path: Path
    password: str
    conversation_states: dict[str, ConversationState]
    key_needs_persistence: bool = False
    legacy_private_key_path: Path | None = None


class IntegrityFailureError(Exception):
    """Raised when encrypted message authentication fails."""


class IncorrectPasswordError(Exception):
    """Raised when the supplied password cannot unlock the private key."""


def slugify_username(username: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", username).strip("._")
    return slug or "user"


def build_username_stem(username: str) -> str:
    username_hash = hashes.Hash(hashes.SHA256())
    username_hash.update(username.encode("utf-8"))
    digest = username_hash.finalize().hex()[:12]
    return f"{slugify_username(username)}_{digest}"


def build_private_key_path(username: str) -> Path:
    return KEY_DIRECTORY / f"{build_username_stem(username)}_private_key.enc.json"


def build_legacy_private_key_path(username: str) -> Path:
    return KEY_DIRECTORY / f"{build_username_stem(username)}_private_key.pem"


def build_legacy_password_path(username: str) -> Path:
    return KEY_DIRECTORY / f"{build_username_stem(username)}_password.txt"


def wipe_bytearray(buffer: bytearray | None) -> None:
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


def clone_bytearray(buffer: bytearray) -> bytearray:
    return bytearray(bytes(buffer))


def best_effort_secure_delete(path: Path) -> None:
    if not path.exists() or not path.is_file():
        return

    try:
        file_size = path.stat().st_size
        with path.open("r+b") as file_handle:
            file_handle.write(b"\x00" * file_size)
            file_handle.flush()
            os.fsync(file_handle.fileno())
    except OSError:
        pass

    try:
        path.unlink()
    except FileNotFoundError:
        return


def encode_public_key(public_key: X25519PublicKey) -> str:
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_public_key).decode("ascii")


def decode_public_key(public_key_b64: str) -> X25519PublicKey:
    raw_public_key = base64.b64decode(public_key_b64, validate=True)
    return X25519PublicKey.from_public_bytes(raw_public_key)


def fingerprint_public_key(public_key: X25519PublicKey) -> str:
    raw_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw_public_key)
    fingerprint = digest.finalize().hex()
    return ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2))


def prompt_password(
    username: str,
    confirm: bool,
    supplied_password: str | None = None,
) -> str:
    if supplied_password is not None:
        if not supplied_password:
            raise ValueError("Password cannot be blank.")
        return supplied_password

    while True:
        password = getpass.getpass(f"Password for {username}: ")
        if not password:
            print("Password cannot be blank.")
            continue

        if not confirm:
            return password

        confirmation = getpass.getpass(f"Confirm password for {username}: ")
        if password != confirmation:
            print("Passwords did not match. Please try again.")
            continue
        return password


def derive_private_key_encryption_key(password: str, salt: bytes) -> bytearray:
    password_buffer = bytearray(password.encode("utf-8"))

    try:
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_SIZE,
            salt=salt,
            iterations=PRIVATE_KEY_ENCRYPTION_ITERATIONS,
        ).derive(bytes(password_buffer))
        return bytearray(derived_key)
    finally:
        wipe_bytearray(password_buffer)


def serialize_conversation_states(
    conversation_states: dict[str, ConversationState],
) -> dict[str, dict[str, Any]]:
    return {
        peer_username: {
            "send_chain_key": base64.b64encode(bytes(state.send_chain_key)).decode("ascii"),
            "send_index": state.send_index,
            "receive_chain_key": base64.b64encode(bytes(state.receive_chain_key)).decode("ascii"),
            "receive_index": state.receive_index,
        }
        for peer_username, state in conversation_states.items()
    }


def deserialize_conversation_states(
    payload: dict[str, Any],
) -> dict[str, ConversationState]:
    conversation_states: dict[str, ConversationState] = {}

    for peer_username, state_payload in payload.items():
        try:
            send_chain_key = bytearray(
                base64.b64decode(state_payload["send_chain_key"], validate=True)
            )
            receive_chain_key = bytearray(
                base64.b64decode(state_payload["receive_chain_key"], validate=True)
            )
            send_index = int(state_payload["send_index"])
            receive_index = int(state_payload["receive_index"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise ValueError(
                f"Conversation state for {peer_username} is malformed."
            ) from exc

        conversation_states[peer_username] = ConversationState(
            send_chain_key=send_chain_key,
            send_index=send_index,
            receive_chain_key=receive_chain_key,
            receive_index=receive_index,
        )

    return conversation_states


def build_identity_state_payload(identity: ClientIdentity) -> bytearray:
    raw_private_key = identity.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key_buffer = bytearray(raw_private_key)

    try:
        payload = {
            "private_key_b64": base64.b64encode(bytes(private_key_buffer)).decode("ascii"),
            "conversation_states": serialize_conversation_states(identity.conversation_states),
        }
        return bytearray(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
    finally:
        wipe_bytearray(private_key_buffer)


def load_identity_state_payload(
    plaintext_buffer: bytearray,
    state_file_path: Path,
) -> tuple[X25519PrivateKey, dict[str, ConversationState]]:
    try:
        payload = json.loads(plaintext_buffer.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        private_key = serialization.load_pem_private_key(bytes(plaintext_buffer), password=None)
        if not isinstance(private_key, X25519PrivateKey):
            raise ValueError(f"{state_file_path} does not contain an X25519 private key.")
        return private_key, {}

    try:
        private_key_bytes = bytearray(
            base64.b64decode(payload["private_key_b64"], validate=True)
        )
        conversation_states = deserialize_conversation_states(
            payload.get("conversation_states", {})
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError(f"{state_file_path} does not contain a valid encrypted identity state.") from exc

    try:
        private_key = X25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
    finally:
        wipe_bytearray(private_key_bytes)

    return private_key, conversation_states


def persist_encrypted_identity_state(identity: ClientIdentity) -> None:
    identity.private_key_path.parent.mkdir(exist_ok=True)

    plaintext_payload = build_identity_state_payload(identity)
    salt = os.urandom(PRIVATE_KEY_ENCRYPTION_SALT_SIZE)
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    encryption_key = derive_private_key_encryption_key(identity.password, salt)

    try:
        ciphertext = AESGCM(bytes(encryption_key)).encrypt(
            nonce,
            bytes(plaintext_payload),
            None,
        )
        envelope = {
            "version": PRIVATE_KEY_FILE_VERSION,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PRIVATE_KEY_ENCRYPTION_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        identity.private_key_path.write_text(json.dumps(envelope), encoding="utf-8")
        os.chmod(identity.private_key_path, 0o600)
    finally:
        wipe_bytearray(plaintext_payload)
        wipe_bytearray(encryption_key)


def load_encrypted_identity_state(
    state_file_path: Path,
    password: str,
) -> tuple[X25519PrivateKey, dict[str, ConversationState]]:
    envelope = json.loads(state_file_path.read_text(encoding="utf-8"))

    try:
        if envelope["version"] != PRIVATE_KEY_FILE_VERSION:
            raise ValueError("Unsupported encrypted identity-state file version.")
        if envelope["iterations"] < PRIVATE_KEY_ENCRYPTION_ITERATIONS:
            raise ValueError("Identity-state file uses too few PBKDF2 iterations.")

        salt = base64.b64decode(envelope["salt"], validate=True)
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise ValueError(f"{state_file_path} is not a valid encrypted identity-state file.") from exc

    encryption_key = derive_private_key_encryption_key(password, salt)
    plaintext_bytes = b""
    plaintext_buffer: bytearray | None = None

    try:
        try:
            plaintext_bytes = AESGCM(bytes(encryption_key)).decrypt(nonce, ciphertext, None)
        except InvalidTag as exc:
            raise IncorrectPasswordError(
                "Incorrect password or corrupted encrypted private key."
            ) from exc

        plaintext_buffer = bytearray(plaintext_bytes)
        return load_identity_state_payload(plaintext_buffer, state_file_path)
    finally:
        wipe_bytearray(encryption_key)
        wipe_bytearray(plaintext_buffer)
        plaintext_bytes = b""


def load_legacy_private_key(private_key_path: Path) -> X25519PrivateKey:
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError(f"{private_key_path} does not contain an X25519 private key.")
    return private_key


def cleanup_legacy_password_artifact(username: str) -> None:
    best_effort_secure_delete(build_legacy_password_path(username))


def persist_identity_state(identity: ClientIdentity) -> None:
    persist_encrypted_identity_state(identity)

    if identity.legacy_private_key_path is not None:
        best_effort_secure_delete(identity.legacy_private_key_path)

    cleanup_legacy_password_artifact(identity.username)
    identity.key_needs_persistence = False
    identity.legacy_private_key_path = None


def load_or_create_identity(
    username: str,
    supplied_password: str | None = None,
) -> tuple[ClientIdentity, bool]:
    KEY_DIRECTORY.mkdir(exist_ok=True)
    private_key_path = build_private_key_path(username)
    legacy_private_key_path = build_legacy_private_key_path(username)

    if private_key_path.exists():
        password = prompt_password(username, confirm=False, supplied_password=supplied_password)
        private_key, conversation_states = load_encrypted_identity_state(private_key_path, password)
        return (
            ClientIdentity(
                username=username,
                private_key=private_key,
                public_key_b64=encode_public_key(private_key.public_key()),
                private_key_path=private_key_path,
                password=password,
                conversation_states=conversation_states,
            ),
            False,
        )

    if legacy_private_key_path.exists():
        password = prompt_password(username, confirm=False, supplied_password=supplied_password)
        private_key = load_legacy_private_key(legacy_private_key_path)
        return (
            ClientIdentity(
                username=username,
                private_key=private_key,
                public_key_b64=encode_public_key(private_key.public_key()),
                private_key_path=private_key_path,
                password=password,
                conversation_states={},
                key_needs_persistence=True,
                legacy_private_key_path=legacy_private_key_path,
            ),
            False,
        )

    password = prompt_password(username, confirm=True, supplied_password=supplied_password)
    private_key = X25519PrivateKey.generate()
    return (
        ClientIdentity(
            username=username,
            private_key=private_key,
            public_key_b64=encode_public_key(private_key.public_key()),
            private_key_path=private_key_path,
            password=password,
            conversation_states={},
            key_needs_persistence=True,
        ),
        True,
    )


def build_auth_headers(identity: ClientIdentity) -> dict[str, str]:
    return {
        "X-Auth-Username": identity.username,
        "X-Auth-Password": identity.password,
    }


def fetch_public_key(
    username: str,
    identity: ClientIdentity,
) -> tuple[X25519PublicKey, str]:
    response = requests.get(
        f"{SERVER_URL}/public-key/{username}",
        headers=build_auth_headers(identity),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()

    try:
        public_key = decode_public_key(payload["public_key"])
    except (KeyError, ValueError, binascii.Error) as exc:
        raise ValueError(f"Server returned an invalid public key for {username}.") from exc

    return public_key, fingerprint_public_key(public_key)


def build_root_key_info(local_username: str, peer_username: str) -> bytes:
    ordered_users = sorted([local_username, peer_username])
    return ROOT_KEY_INFO_PREFIX + "|".join(ordered_users).encode("utf-8")


def build_chain_key_info(sender_username: str, recipient_username: str) -> bytes:
    return CHAIN_KEY_INFO_PREFIX + f"{sender_username}->{recipient_username}".encode("utf-8")


def build_message_aad(sender_id: str, recipient_id: str, message_id: str) -> bytes:
    aad_payload = {
        "message_id": message_id,
        "recipient_id": recipient_id,
        "sender_id": sender_id,
    }
    return json.dumps(aad_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_root_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    local_username: str,
    peer_username: str,
) -> bytearray:
    shared_secret_bytes = private_key.exchange(peer_public_key)
    shared_secret_buffer = bytearray(shared_secret_bytes)

    try:
        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_SIZE,
            salt=None,
            info=build_root_key_info(local_username, peer_username),
        ).derive(bytes(shared_secret_buffer))
        return bytearray(root_key)
    finally:
        wipe_bytearray(shared_secret_buffer)
        shared_secret_bytes = b""


def derive_initial_chain_key(root_key: bytearray, sender_username: str, recipient_username: str) -> bytearray:
    derived_chain_key = HKDF(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_SIZE,
        salt=None,
        info=build_chain_key_info(sender_username, recipient_username),
    ).derive(bytes(root_key))
    return bytearray(derived_chain_key)


def get_or_create_conversation_state(
    identity: ClientIdentity,
    peer_username: str,
    peer_public_key: X25519PublicKey,
) -> ConversationState:
    existing_state = identity.conversation_states.get(peer_username)
    if existing_state is not None:
        return existing_state

    root_key = derive_root_key(
        identity.private_key,
        peer_public_key,
        identity.username,
        peer_username,
    )

    try:
        send_chain_key = derive_initial_chain_key(root_key, identity.username, peer_username)
        receive_chain_key = derive_initial_chain_key(root_key, peer_username, identity.username)
    finally:
        wipe_bytearray(root_key)

    conversation_state = ConversationState(
        send_chain_key=send_chain_key,
        send_index=0,
        receive_chain_key=receive_chain_key,
        receive_index=0,
    )
    identity.conversation_states[peer_username] = conversation_state
    return conversation_state


def derive_chain_step(current_chain_key: bytearray) -> tuple[bytearray, bytearray]:
    derived_material = HKDF(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_SIZE * 2,
        salt=None,
        info=CHAIN_STEP_INFO,
    ).derive(bytes(current_chain_key))
    return (
        bytearray(derived_material[:SYMMETRIC_KEY_SIZE]),
        bytearray(derived_material[SYMMETRIC_KEY_SIZE:]),
    )


def commit_send_chain_step(
    identity: ClientIdentity,
    peer_username: str,
    next_chain_key: bytearray,
) -> None:
    conversation_state = identity.conversation_states[peer_username]
    wipe_bytearray(conversation_state.send_chain_key)
    conversation_state.send_chain_key = next_chain_key
    conversation_state.send_index += 1
    persist_identity_state(identity)


def commit_receive_chain_step(
    identity: ClientIdentity,
    peer_username: str,
    next_chain_key: bytearray,
    next_receive_index: int,
) -> None:
    conversation_state = identity.conversation_states[peer_username]
    wipe_bytearray(conversation_state.receive_chain_key)
    conversation_state.receive_chain_key = next_chain_key
    conversation_state.receive_index = next_receive_index
    persist_identity_state(identity)


def protect_outbound_content(
    identity: ClientIdentity,
    plaintext: str,
    recipient: str,
    recipient_public_key: X25519PublicKey,
    message_id: str,
    verbose: bool = False,
) -> tuple[str, bytearray, int]:
    conversation_state = get_or_create_conversation_state(identity, recipient, recipient_public_key)
    next_chain_key, message_key = derive_chain_step(conversation_state.send_chain_key)
    chain_index = conversation_state.send_index
    aad = build_message_aad(identity.username, recipient, message_id)

    try:
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext_and_tag = AESGCM(bytes(message_key)).encrypt(
            nonce,
            plaintext.encode("utf-8"),
            aad,
        )
        encoded_ciphertext = base64.b64encode(nonce + ciphertext_and_tag).decode("ascii")
        if verbose:
            print(f"Outgoing ciphertext (Base64): {encoded_ciphertext}")
        return encoded_ciphertext, next_chain_key, chain_index
    except Exception:
        wipe_bytearray(next_chain_key)
        raise
    finally:
        wipe_bytearray(message_key)


def derive_receive_material(
    conversation_state: ConversationState,
    target_index: int,
) -> tuple[bytearray, bytearray]:
    if target_index < conversation_state.receive_index:
        raise IntegrityFailureError("Replay Attack detected: duplicate or stale chain index.")

    working_chain_key = clone_bytearray(conversation_state.receive_chain_key)

    try:
        for chain_index in range(conversation_state.receive_index, target_index + 1):
            next_chain_key, message_key = derive_chain_step(working_chain_key)
            wipe_bytearray(working_chain_key)

            if chain_index == target_index:
                return next_chain_key, message_key

            wipe_bytearray(message_key)
            working_chain_key = next_chain_key
    finally:
        wipe_bytearray(working_chain_key)

    raise IntegrityFailureError("Could not derive the requested message key.")


def recover_inbound_content(
    identity: ClientIdentity,
    message: dict[str, Any],
    sender_public_key: X25519PublicKey,
    verbose: bool = False,
) -> tuple[str, bytearray, int]:
    if verbose:
        print(f"Received ciphertext (Base64): {message['content']}")

    try:
        encrypted_payload = base64.b64decode(message["content"], validate=True)
    except binascii.Error as exc:
        raise IntegrityFailureError("Integrity Failure: malformed encrypted payload.") from exc

    if len(encrypted_payload) <= AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise IntegrityFailureError("Integrity Failure: malformed encrypted payload.")

    target_chain_index = int(message["chain_index"])
    conversation_state = get_or_create_conversation_state(
        identity,
        message["sender"],
        sender_public_key,
    )
    next_chain_key, message_key = derive_receive_material(conversation_state, target_chain_index)
    aad = build_message_aad(message["sender"], message["recipient"], message["id"])

    try:
        nonce = encrypted_payload[:AES_GCM_NONCE_SIZE]
        ciphertext = encrypted_payload[AES_GCM_NONCE_SIZE:-AES_GCM_TAG_SIZE]
        tag = encrypted_payload[-AES_GCM_TAG_SIZE:]
        ciphertext_and_tag = ciphertext + tag

        try:
            plaintext_bytes = AESGCM(bytes(message_key)).decrypt(
                nonce,
                ciphertext_and_tag,
                aad,
            )
        except InvalidTag as exc:
            raise IntegrityFailureError(
                "Integrity Failure: message authentication failed."
            ) from exc

        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Decrypted message is not valid UTF-8.") from exc

        return plaintext, next_chain_key, target_chain_index + 1
    except Exception:
        wipe_bytearray(next_chain_key)
        raise
    finally:
        wipe_bytearray(message_key)


def register_user(identity: ClientIdentity) -> bool:
    response = requests.post(
        f"{SERVER_URL}/register",
        json={
            "username": identity.username,
            "public_key": identity.public_key_b64,
            "password": identity.password,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if not response.ok:
        print_request_error(response)
        return False

    persist_identity_state(identity)

    payload = response.json()
    if payload["already_registered"]:
        print(f"{identity.username} is already registered with the same credentials.")
    else:
        print(f"{identity.username} registered successfully with authenticated E2EE credentials.")
    return True


def prompt_fingerprint_acknowledgement(recipient: str, fingerprint: str) -> bool:
    print(f"Recipient fingerprint for {recipient}: {fingerprint}")
    print(
        "Security warning: Encryption is only as secure as the identity verification. "
        "If you have not verified this fingerprint out-of-band, your conversation may be intercepted."
    )
    confirmation = input(
        "Type 'verified' only if you have confirmed this fingerprint out-of-band: "
    ).strip()
    if confirmation.lower() != "verified":
        print("Message send cancelled because fingerprint verification was not confirmed.")
        return False
    return True


def parse_queued_at(queued_at: str) -> datetime:
    try:
        parsed_timestamp = datetime.fromisoformat(queued_at)
    except ValueError as exc:
        raise ValueError(f"Invalid queued_at timestamp: {queued_at}") from exc

    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(tzinfo=timezone.utc)

    return parsed_timestamp.astimezone(timezone.utc)


def is_message_expired(queued_at: str) -> bool:
    message_time = parse_queued_at(queued_at)
    return datetime.now(timezone.utc) - message_time > MESSAGE_MAX_AGE


def prompt_replay_warning(message: dict[str, Any]) -> bool:
    message_time = parse_queued_at(message["queued_at"])
    message_age = datetime.now(timezone.utc) - message_time
    print("Warning: Potential Replay Attack or Expired Message.")
    print(f"Message age: {message_age}.")
    confirmation = input(
        "Type 'yes' to decrypt anyway or anything else to skip this message: "
    ).strip()
    return confirmation.lower() in {"y", "yes"}


def send_message(identity: ClientIdentity, verbose: bool = False) -> None:
    recipient = input("Recipient: ").strip()
    plaintext = input("Message: ").strip()

    if not recipient or not plaintext:
        print("Recipient and message are both required.")
        return

    recipient_public_key, fingerprint = fetch_public_key(recipient, identity)
    if not prompt_fingerprint_acknowledgement(recipient, fingerprint):
        return

    message_id = str(uuid4())
    next_chain_key: bytearray | None = None

    try:
        protected_content, next_chain_key, chain_index = protect_outbound_content(
            identity,
            plaintext,
            recipient,
            recipient_public_key,
            message_id,
            verbose=verbose,
        )

        response = requests.post(
            f"{SERVER_URL}/send",
            json={
                "message_id": message_id,
                "sender": identity.username,
                "recipient": recipient,
                "content": protected_content,
                "chain_index": chain_index,
            },
            headers=build_auth_headers(identity),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )

        if response.ok:
            payload = response.json()
            commit_send_chain_step(identity, recipient, next_chain_key)
            next_chain_key = None
            print(f"Queued message {payload['message_id']} for {payload['recipient']}.")
            return

        print_request_error(response)
    finally:
        wipe_bytearray(next_chain_key)


def check_messages(identity: ClientIdentity, verbose: bool = False) -> None:
    response = requests.get(
        f"{SERVER_URL}/messages/{identity.username}",
        headers=build_auth_headers(identity),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    if not response.ok:
        print_request_error(response)
        return

    payload = response.json()
    messages = payload["messages"]

    if not messages:
        print("No new messages.")
        return

    print(f"\n{len(messages)} new message(s):")
    for message in messages:
        print("-" * 40)
        print(f"From: {message['sender']}")
        print(f"Queued: {message['queued_at']}")
        print(f"Message ID: {message['id']}")
        try:
            if is_message_expired(message["queued_at"]) and not prompt_replay_warning(message):
                print("Skipped message after replay/expiry warning.")
                continue

            sender_public_key, _ = fetch_public_key(message["sender"], identity)
            plaintext, next_chain_key, next_receive_index = recover_inbound_content(
                identity,
                message,
                sender_public_key,
                verbose=verbose,
            )
            commit_receive_chain_step(
                identity,
                message["sender"],
                next_chain_key,
                next_receive_index,
            )
            print(f"Message: {plaintext}")
        except IntegrityFailureError as exc:
            print(str(exc))
        except ValueError as exc:
            print(f"Could not decode message: {exc}")
    print("-" * 40)


def print_request_error(response: requests.Response) -> None:
    try:
        detail = response.json().get("detail", response.text)
    except ValueError:
        detail = response.text
    print(f"Request failed ({response.status_code}): {detail}")


def prompt_menu_choice() -> str:
    print("\nChoose an action:")
    print("1. Send message")
    print("2. Check messages")
    print("3. Exit")
    return input("> ").strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hardened client for the local messaging relay."
    )
    parser.add_argument(
        "username",
        nargs="?",
        help="Username to register and use for this client session.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print raw Base64 ciphertext before send and after receipt.",
    )
    parser.add_argument(
        "--server-url",
        default=SERVER_URL,
        help=(
            "Relay server URL. Defaults to E2EE_SERVER_URL, SERVER_URL, "
            "or http://127.0.0.1:8000."
        ),
    )
    return parser.parse_args()


def main() -> None:
    global SERVER_URL

    args = parse_args()
    SERVER_URL = normalize_server_url(args.server_url)
    username = (args.username or input("Username: ")).strip()

    if not username:
        print("A username is required.")
        return

    print(f"Using relay server: {SERVER_URL}")

    try:
        identity, created_now = load_or_create_identity(username)

        if identity.key_needs_persistence and identity.legacy_private_key_path is not None:
            print(
                "Loaded a legacy plaintext private key. It will be re-encrypted on disk "
                "after successful authentication."
            )
        elif created_now:
            print(
                "Generated a new key pair in memory. It will be encrypted and saved "
                "after successful registration."
            )
        else:
            print(f"Loaded encrypted identity state from {identity.private_key_path}.")

        if not register_user(identity):
            raise SystemExit(1)
    except IncorrectPasswordError as exc:
        print(str(exc))
        raise SystemExit(1) from exc
    except (OSError, ValueError) as exc:
        print(f"Could not initialize local identity: {exc}")
        raise SystemExit(1) from exc
    except requests.RequestException as exc:
        print(f"Could not reach the server at {SERVER_URL}: {exc}")
        raise SystemExit(1) from exc

    while True:
        choice = prompt_menu_choice()

        try:
            if choice == "1":
                send_message(identity, verbose=args.verbose)
            elif choice == "2":
                check_messages(identity, verbose=args.verbose)
            elif choice == "3":
                print("Goodbye.")
                return
            else:
                print("Please choose 1, 2, or 3.")
        except requests.HTTPError as exc:
            if exc.response is not None:
                print_request_error(exc.response)
            else:
                print(f"Request failed: {exc}")
        except ValueError as exc:
            print(f"Security error: {exc}")
        except requests.RequestException as exc:
            print(f"Network error: {exc}")


if __name__ == "__main__":
    main()
