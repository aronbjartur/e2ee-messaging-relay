from __future__ import annotations

import base64
from uuid import uuid4

import requests

from client import (
    REQUEST_TIMEOUT_SECONDS,
    SERVER_URL,
    IntegrityFailureError,
    build_auth_headers,
    commit_send_chain_step,
    fetch_public_key,
    load_or_create_identity,
    protect_outbound_content,
    recover_inbound_content,
    register_user,
)
from server import get_connection


def ensure_registered(username: str, password: str):
    identity, created_now = load_or_create_identity(username, supplied_password=password)

    if identity.key_needs_persistence and identity.legacy_private_key_path is not None:
        print(f"Loaded legacy private key for {username} and will re-encrypt it after auth.")
    elif created_now:
        print(f"Generated new in-memory key pair for {username}.")
    else:
        print(f"Loaded encrypted identity state for {username}.")

    if not register_user(identity):
        raise RuntimeError(f"Could not register {username}.")

    return identity


def send_encrypted_message(sender_identity, recipient: str, plaintext: str) -> str:
    recipient_public_key, fingerprint = fetch_public_key(recipient, sender_identity)
    print(f"Recipient fingerprint for {recipient}: {fingerprint}")

    message_id = str(uuid4())
    ciphertext, next_chain_key, chain_index = protect_outbound_content(
        sender_identity,
        plaintext,
        recipient,
        recipient_public_key,
        message_id,
        verbose=True,
    )

    response = requests.post(
        f"{SERVER_URL}/send",
        json={
            "message_id": message_id,
            "sender": sender_identity.username,
            "recipient": recipient,
            "content": ciphertext,
            "chain_index": chain_index,
        },
        headers=build_auth_headers(sender_identity),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    commit_send_chain_step(sender_identity, recipient, next_chain_key)
    print(f"Queued encrypted message {message_id}.")
    return message_id


def mutate_message_id_in_postgres(message_id: str) -> str:
    replacement_id = str(uuid4())
    with get_connection() as connection:
        connection.execute(
            "UPDATE messages SET id = %s WHERE id = %s",
            (replacement_id, message_id),
        )
    print(f"Retagged stored message ID from {message_id} to {replacement_id}.")
    return replacement_id


def tamper_ciphertext_in_postgres(message_id: str) -> None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT content FROM messages WHERE id = %s",
            (message_id,),
        ).fetchone()
        if row is None:
            raise RuntimeError(f"Message {message_id} was not found in PostgreSQL.")

        raw_payload = base64.b64decode(row["content"], validate=True)
        tampered_payload = bytearray(raw_payload)
        tampered_payload[-1] ^= 0x01
        tampered_content = base64.b64encode(bytes(tampered_payload)).decode("ascii")

        connection.execute(
            "UPDATE messages SET content = %s WHERE id = %s",
            (tampered_content, message_id),
        )

    print(f"Tampered with stored ciphertext for message {message_id} directly in PostgreSQL.")


def fetch_pending_messages(identity) -> list[dict[str, object]]:
    response = requests.get(
        f"{SERVER_URL}/messages/{identity.username}",
        headers=build_auth_headers(identity),
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    payload = response.json()
    return payload["messages"]


def expect_integrity_failure(identity, message: dict[str, object], label: str) -> None:
    sender_public_key, _ = fetch_public_key(str(message["sender"]), identity)

    try:
        recover_inbound_content(
            identity,
            message,
            sender_public_key,
            verbose=True,
        )
    except IntegrityFailureError as exc:
        print(f"PASS ({label}): {exc}")
        return

    raise RuntimeError(f"FAIL ({label}): expected IntegrityFailureError, but decryption succeeded.")


def run_aad_metadata_test(suffix: str) -> None:
    alice_username = f"aad_alice_{suffix}"
    bob_username = f"aad_bob_{suffix}"
    alice_password = f"alice-pass-{suffix}"
    bob_password = f"bob-pass-{suffix}"

    alice_identity = ensure_registered(alice_username, alice_password)
    bob_identity = ensure_registered(bob_username, bob_password)

    original_message_id = send_encrypted_message(
        alice_identity,
        bob_username,
        "metadata-binding-check",
    )
    mutate_message_id_in_postgres(original_message_id)

    messages = fetch_pending_messages(bob_identity)
    if len(messages) != 1:
        raise RuntimeError(f"AAD test expected one queued message, found {len(messages)}.")

    expect_integrity_failure(bob_identity, messages[0], "AAD metadata binding")


def run_ciphertext_tamper_test(suffix: str) -> None:
    alice_username = f"tamper_alice_{suffix}"
    bob_username = f"tamper_bob_{suffix}"
    alice_password = f"alice-pass-{suffix}"
    bob_password = f"bob-pass-{suffix}"

    alice_identity = ensure_registered(alice_username, alice_password)
    bob_identity = ensure_registered(bob_username, bob_password)

    message_id = send_encrypted_message(
        alice_identity,
        bob_username,
        "ciphertext-integrity-check",
    )
    tamper_ciphertext_in_postgres(message_id)

    messages = fetch_pending_messages(bob_identity)
    if len(messages) != 1:
        raise RuntimeError(f"Ciphertext test expected one queued message, found {len(messages)}.")

    expect_integrity_failure(bob_identity, messages[0], "Ciphertext tampering")


def main() -> None:
    suffix = uuid4().hex[:8]
    run_aad_metadata_test(f"{suffix}_aad")
    run_ciphertext_tamper_test(f"{suffix}_ct")
    print("All evil-server tests passed.")


if __name__ == "__main__":
    main()
