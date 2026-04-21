from __future__ import annotations

import base64
import binascii
import json
import os
import threading
from pathlib import Path
from uuid import uuid4

import customtkinter as ctk
import requests

import client as e2ee


SERVER_URL = e2ee.normalize_server_url("https://e2ee-chat-jfml.onrender.com")
e2ee.SERVER_URL = SERVER_URL

BG = "#000000"
HEADER = "#FFFFFF"
TERM = "#00FF00"
ERROR = "#FF5555"


class RelayApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.identity = None
        self.lock_path: Path | None = None
        self.trust_store_path: Path | None = None
        self.closing = False
        self.seen_ids: set[str] = set()
        self.trusted_fingerprints: dict[str, str] = {}
        self.title("E2EE Relay")
        self.geometry("760x560")
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.shutdown)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("green")
        self._build_auth()

    def clear(self) -> None:
        for widget in self.winfo_children():
            widget.destroy()

    def _entry(self, parent, placeholder: str, secret: bool = False):
        return ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            show="*" if secret else "",
            fg_color=BG,
            text_color=TERM,
            border_color=TERM,
        )

    def _button(self, parent, text: str, command):
        return ctk.CTkButton(
            parent,
            text=text,
            command=command,
            fg_color=TERM,
            hover_color="#33FF33",
            text_color=BG,
        )

    def _build_auth(self) -> None:
        self.clear()
        frame = ctk.CTkFrame(self, fg_color=BG, border_color=TERM, border_width=1)
        frame.pack(expand=True, fill="both", padx=36, pady=36)
        ctk.CTkLabel(
            frame,
            text="E2EE RELAY",
            font=("Menlo", 28, "bold"),
            text_color=HEADER,
        ).pack(pady=(42, 10))
        ctk.CTkLabel(
            frame,
            text="Local encrypted identity required. Password is never saved.",
            text_color=TERM,
        ).pack(pady=(0, 24))
        self.username = self._entry(frame, "username")
        self.username.pack(fill="x", padx=90, pady=8)
        self.password = self._entry(frame, "password", secret=True)
        self.password.pack(fill="x", padx=90, pady=8)

        buttons = ctk.CTkFrame(frame, fg_color=BG)
        buttons.pack(fill="x", padx=90, pady=18)
        self._button(buttons, "[REGISTER]", lambda: self.auth(create=True)).pack(
            side="left",
            expand=True,
            fill="x",
            padx=(0, 6),
        )
        self._button(buttons, "[LOGIN]", lambda: self.auth(create=False)).pack(
            side="left",
            expand=True,
            fill="x",
            padx=(6, 0),
        )
        self.status = ctk.CTkLabel(frame, text="", text_color=TERM)
        self.status.pack(pady=6)

    def _build_chat(self) -> None:
        self.clear()
        root = ctk.CTkFrame(self, fg_color=BG)
        root.pack(expand=True, fill="both", padx=14, pady=14)
        header = ctk.CTkFrame(root, fg_color=BG, border_color=TERM, border_width=1)
        header.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            header,
            text=f"USER: {self.identity.username}",
            text_color=HEADER,
            font=("Menlo", 15, "bold"),
        ).pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(
            header,
            text="CONNECTION STATUS: ACTIVE (ENCRYPTED)",
            text_color=TERM,
            font=("Menlo", 13, "bold"),
        ).pack(side="left", padx=20)
        self._button(header, "[LOGOUT]", self.logout).pack(side="right", padx=10, pady=8)
        fingerprint_frame = ctk.CTkFrame(root, fg_color=BG, border_color=TERM, border_width=1)
        fingerprint_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(
            fingerprint_frame,
            text="MY FINGERPRINT",
            text_color=HEADER,
            font=("Menlo", 13, "bold"),
        ).pack(anchor="w", padx=10, pady=(8, 2))
        fingerprint_box = ctk.CTkTextbox(
            fingerprint_frame,
            height=52,
            fg_color=BG,
            text_color=TERM,
            border_width=0,
            font=("Menlo", 12),
            wrap="word",
        )
        fingerprint_box.pack(fill="x", padx=10, pady=(0, 8))
        fingerprint_box.insert("end", self.my_fingerprint())
        fingerprint_box.configure(state="disabled")
        self.chat = ctk.CTkTextbox(
            root,
            fg_color=BG,
            text_color=TERM,
            border_color=TERM,
            border_width=1,
            font=("Menlo", 13),
        )
        self.chat.pack(expand=True, fill="both")
        bottom = ctk.CTkFrame(root, fg_color=BG)
        bottom.pack(fill="x", pady=(10, 0))
        self.recipient = self._entry(bottom, "recipient")
        self.recipient.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=4)
        self.message = self._entry(bottom, "message")
        self.message.grid(row=1, column=0, sticky="ew", padx=(0, 8), pady=4)
        self.message.bind("<Return>", lambda _event: self.send_message())
        self._button(bottom, "[SEND]", self.send_message).grid(
            row=0,
            column=1,
            rowspan=2,
            sticky="nsew",
            padx=4,
        )
        self._button(bottom, "[REFRESH]", self.refresh).grid(
            row=0,
            column=2,
            rowspan=2,
            sticky="nsew",
            padx=(4, 0),
        )
        bottom.columnconfigure(0, weight=1)
        self.chat_status = ctk.CTkLabel(root, text=f"SERVER: {SERVER_URL}", text_color=TERM)
        self.chat_status.pack(anchor="w", pady=(8, 0))
        self.append("SYSTEM", "ready. messages are encrypted before they leave this app.")

    def append(self, sender: str, text: str) -> None:
        self.chat.configure(state="normal")
        self.chat.insert("end", f"[{sender}] {text}\n")
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def set_status(self, text: str, error: bool = False) -> None:
        label = self.status if self.identity is None else self.chat_status
        label.configure(text=text, text_color=ERROR if error else TERM)

    def run_task(self, work, done=None, on_error=None) -> None:
        self.set_status("WORKING...")

        def worker() -> None:
            try:
                result = work()
            except Exception as exc:
                message = self.friendly_error(exc)

                def fail() -> None:
                    if on_error is not None:
                        on_error(message)
                    else:
                        self.set_status(message, True)

                if not self.closing:
                    self.after(0, fail)
            else:
                if not self.closing:
                    self.after(0, lambda: done(result) if done else self.set_status("DONE."))

        threading.Thread(target=worker, daemon=True).start()

    def friendly_error(self, exc: Exception) -> str:
        if isinstance(exc, e2ee.IncorrectPasswordError):
            return "Incorrect password or corrupted local identity."
        if isinstance(exc, requests.HTTPError) and exc.response is not None:
            return self.response_error(exc.response)
        if isinstance(exc, requests.RequestException):
            return f"Network/server error: {exc}"
        return str(exc)

    def response_error(self, response: requests.Response) -> str:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        return f"Request failed ({response.status_code}): {detail}"

    def auth(self, create: bool) -> None:
        username = self.username.get().strip()
        password = self.password.get()
        self.password.delete(0, "end")
        if not username or not password:
            self.set_status("username and password are required.", True)
            return
        try:
            self.acquire_lock(username)
        except RuntimeError as exc:
            self.set_status(str(exc), True)
            return

        def work():
            if not create and not self.local_identity_exists(username):
                raise RuntimeError("No local identity found. Use [REGISTER] first.")
            identity, _created = e2ee.load_or_create_identity(
                username,
                supplied_password=password,
            )
            self.register_with_server(identity)
            return identity

        def done(identity) -> None:
            self.identity = identity
            self.trust_store_path = self.trust_store_for(identity.username)
            self.trusted_fingerprints = self.load_trust_store()
            self._build_chat()

        def failed(message: str) -> None:
            self.release_lock()
            self.set_status(message, True)

        self.run_task(work, done, failed)

    def local_identity_exists(self, username: str) -> bool:
        return (
            e2ee.build_private_key_path(username).exists()
            or e2ee.build_legacy_private_key_path(username).exists()
        )

    def lock_file_for(self, username: str) -> Path:
        return e2ee.KEY_DIRECTORY / f"{e2ee.build_username_stem(username)}.lock"

    def trust_store_for(self, username: str) -> Path:
        stem = e2ee.build_username_stem(username)
        return e2ee.KEY_DIRECTORY / f"{stem}_trusted_fingerprints.json"

    def load_trust_store(self) -> dict[str, str]:
        if self.trust_store_path is None or not self.trust_store_path.exists():
            return {}
        try:
            payload = json.loads(self.trust_store_path.read_text(encoding="utf-8"))
            contacts = payload.get("contacts", {})
            return {
                str(contact): str(fingerprint)
                for contact, fingerprint in contacts.items()
                if isinstance(contact, str) and isinstance(fingerprint, str)
            }
        except (OSError, json.JSONDecodeError):
            return {}

    def save_trust_store(self) -> None:
        if self.trust_store_path is None:
            return
        self.trust_store_path.parent.mkdir(exist_ok=True)
        payload = {"contacts": dict(sorted(self.trusted_fingerprints.items()))}
        temporary_path = self.trust_store_path.with_name(f"{self.trust_store_path.name}.tmp")
        temporary_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.chmod(temporary_path, 0o600)
        temporary_path.replace(self.trust_store_path)

    def trust_fingerprint(self, username: str, fingerprint: str) -> None:
        self.trusted_fingerprints[username] = fingerprint
        self.save_trust_store()

    def my_fingerprint(self) -> str:
        return e2ee.fingerprint_public_key(self.identity.private_key.public_key())

    def acquire_lock(self, username: str) -> None:
        e2ee.KEY_DIRECTORY.mkdir(exist_ok=True)
        lock_path = self.lock_file_for(username)
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError("User already active on this system.") from exc
        with os.fdopen(fd, "w", encoding="utf-8") as lock_file:
            lock_file.write(f"{os.getpid()}\n")
        self.lock_path = lock_path

    def release_lock(self) -> None:
        if self.lock_path is None:
            return
        try:
            self.lock_path.unlink()
        except FileNotFoundError:
            pass
        self.lock_path = None

    def register_with_server(self, identity) -> None:
        response = requests.post(
            f"{SERVER_URL}/register",
            json={
                "username": identity.username,
                "public_key": identity.public_key_b64,
                "password": identity.password,
            },
            timeout=e2ee.REQUEST_TIMEOUT_SECONDS,
        )
        if not response.ok:
            raise requests.HTTPError(self.response_error(response), response=response)
        e2ee.persist_identity_state(identity)

    def send_message(self) -> None:
        recipient = self.recipient.get().strip()
        plaintext = self.message.get().strip()
        if not recipient or not plaintext:
            self.set_status("recipient and message are required.", True)
            return

        def fetch_peer():
            return e2ee.fetch_public_key(recipient, self.identity)

        def confirm(peer_info) -> None:
            peer_key, fingerprint = peer_info
            stored_fingerprint = self.trusted_fingerprints.get(recipient)
            if stored_fingerprint != fingerprint:
                if not self.confirm_fingerprint(recipient, fingerprint, stored_fingerprint):
                    self.set_status("send cancelled: fingerprint not verified.", True)
                    return
                try:
                    self.trust_fingerprint(recipient, fingerprint)
                except OSError as exc:
                    self.set_status(f"could not save trusted fingerprint: {exc}", True)
                    return
            self.run_task(lambda: self._send_encrypted(recipient, plaintext, peer_key), self._sent)

        self.run_task(fetch_peer, confirm)

    def confirm_fingerprint(
        self,
        recipient: str,
        fingerprint: str,
        stored_fingerprint: str | None,
    ) -> bool:
        result = {"confirmed": False}
        changed = stored_fingerprint is not None
        dialog = ctk.CTkToplevel(self)
        dialog.title("Verify Fingerprint")
        dialog.configure(fg_color=BG)
        dialog.transient(self)
        dialog.grab_set()
        dialog.geometry("620x440" if changed else "620x360")
        ctk.CTkLabel(
            dialog,
            text="CONTACT KEY CHANGED" if changed else "VERIFY RECIPIENT IDENTITY",
            text_color=ERROR if changed else HEADER,
            font=("Menlo", 18, "bold"),
        ).pack(pady=(24, 8))
        warning = (
            "WARNING: The stored fingerprint for this contact is different. "
            "This may be a new device, account reset, or an impersonation attempt."
            if changed
            else (
                "First time sending to this contact. Compare this fingerprint against "
                "the MY FINGERPRINT value shown on the recipient's own device, or use "
                "another trusted channel such as an in-person check or verified call."
            )
        )
        ctk.CTkLabel(
            dialog,
            text=warning,
            text_color=ERROR if changed else TERM,
            wraplength=560,
            justify="left",
        ).pack(fill="x", padx=24, pady=(0, 10))
        ctk.CTkLabel(dialog, text=f"RECIPIENT: {recipient}", text_color=HEADER).pack()
        if changed:
            self._fingerprint_box(dialog, "PREVIOUSLY TRUSTED", stored_fingerprint, ERROR)
        self._fingerprint_box(dialog, "CURRENT FINGERPRINT", fingerprint, TERM)
        ctk.CTkLabel(
            dialog,
            text="Only continue if the recipient confirms this exact value.",
            text_color=TERM,
        ).pack(pady=(0, 12))
        buttons = ctk.CTkFrame(dialog, fg_color=BG)
        buttons.pack(fill="x", padx=24)

        def accept() -> None:
            result["confirmed"] = True
            dialog.destroy()

        self._button(buttons, "[I VERIFIED]", accept).pack(side="left", expand=True, fill="x")
        self._button(buttons, "[CANCEL]", dialog.destroy).pack(
            side="left",
            expand=True,
            fill="x",
            padx=(12, 0),
        )
        self.wait_window(dialog)
        return result["confirmed"]

    def _fingerprint_box(self, parent, title: str, fingerprint: str, color: str) -> None:
        ctk.CTkLabel(parent, text=title, text_color=HEADER, font=("Menlo", 12, "bold")).pack(
            anchor="w",
            padx=24,
        )
        textbox = ctk.CTkTextbox(
            parent,
            height=74,
            fg_color=BG,
            text_color=color,
            border_color=color,
            border_width=1,
            font=("Menlo", 12),
            wrap="word",
        )
        textbox.pack(fill="x", padx=24, pady=12)
        textbox.insert("end", fingerprint)
        textbox.configure(state="disabled")

    def valid_encrypted_payload(self, content: str) -> bool:
        try:
            raw = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            return False
        minimum_size = e2ee.AES_GCM_NONCE_SIZE + e2ee.AES_GCM_TAG_SIZE
        return len(raw) > minimum_size

    def _send_encrypted(self, recipient, plaintext, peer_key) -> tuple[str, str, str]:
        message_id = str(uuid4())
        next_chain_key = None
        receive_chain_key = None
        try:
            content, next_chain_key, chain_index = e2ee.protect_outbound_content(
                self.identity,
                plaintext,
                recipient,
                peer_key,
                message_id,
            )
            if not self.valid_encrypted_payload(content):
                raise RuntimeError("Internal encryption error: invalid encrypted payload.")
            response = requests.post(
                f"{SERVER_URL}/send",
                json={
                    "message_id": message_id,
                    "sender": self.identity.username,
                    "recipient": recipient,
                    "content": content,
                    "chain_index": chain_index,
                },
                headers=e2ee.build_auth_headers(self.identity),
                timeout=e2ee.REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            if recipient == self.identity.username:
                receive_chain_key = e2ee.clone_bytearray(next_chain_key)
            e2ee.commit_send_chain_step(self.identity, recipient, next_chain_key)
            next_chain_key = None
            if receive_chain_key is not None:
                e2ee.commit_receive_chain_step(
                    self.identity,
                    recipient,
                    receive_chain_key,
                    chain_index + 1,
                )
                receive_chain_key = None
            return recipient, plaintext, message_id
        finally:
            e2ee.wipe_bytearray(next_chain_key)
            e2ee.wipe_bytearray(receive_chain_key)

    def _sent(self, result: tuple[str, str, str]) -> None:
        recipient, plaintext, message_id = result
        if recipient == self.identity.username:
            self.seen_ids.add(message_id)
        self.message.delete(0, "end")
        self.append(f"ME -> {recipient}", plaintext)
        self.set_status("SENT ENCRYPTED MESSAGE.")

    def refresh(self) -> None:
        self.run_task(self._fetch_messages, self._show_messages)

    def _fetch_messages(self) -> list[tuple[str, str, bool]]:
        response = requests.get(
            f"{SERVER_URL}/messages/{self.identity.username}",
            headers=e2ee.build_auth_headers(self.identity),
            timeout=e2ee.REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        output = []
        for message in response.json()["messages"]:
            if message["id"] in self.seen_ids:
                continue
            if self.self_message_already_consumed(message):
                self.seen_ids.add(message["id"])
                continue
            self.seen_ids.add(message["id"])
            try:
                sender_key, _fingerprint = e2ee.fetch_public_key(message["sender"], self.identity)
                plaintext, next_key, next_index = e2ee.recover_inbound_content(
                    self.identity,
                    message,
                    sender_key,
                )
                e2ee.commit_receive_chain_step(
                    self.identity,
                    message["sender"],
                    next_key,
                    next_index,
                )
                output.append((message["sender"], plaintext, False))
            except e2ee.IntegrityFailureError:
                output.append(
                    (
                        "ERROR",
                        "Session out of sync or replay detected. Please restart for security.",
                        True,
                    )
                )
        return output

    def self_message_already_consumed(self, message: dict[str, object]) -> bool:
        if message.get("sender") != self.identity.username:
            return False
        if message.get("recipient") != self.identity.username:
            return False
        state = self.identity.conversation_states.get(self.identity.username)
        if state is None:
            return False
        try:
            return int(message["chain_index"]) < state.receive_index
        except (KeyError, TypeError, ValueError):
            return False

    def _show_messages(self, messages: list[tuple[str, str, bool]]) -> None:
        if not messages:
            self.set_status("NO NEW MESSAGES.")
            return
        for sender, text, failed in messages:
            self.append(sender, ("ERROR: " if failed else "") + text)
        self.set_status(f"LOADED {len(messages)} MESSAGE(S).")

    def clear_sensitive_state(self) -> None:
        if self.identity is not None:
            for state in self.identity.conversation_states.values():
                e2ee.wipe_bytearray(state.send_chain_key)
                e2ee.wipe_bytearray(state.receive_chain_key)
            self.identity.conversation_states.clear()
            self.identity.password = ""
        self.identity = None
        self.seen_ids.clear()
        self.trusted_fingerprints.clear()
        self.trust_store_path = None

    def logout(self) -> None:
        self.clear_sensitive_state()
        self.release_lock()
        self._build_auth()

    def shutdown(self) -> None:
        self.closing = True
        self.clear_sensitive_state()
        self.release_lock()
        self.destroy()


if __name__ == "__main__":
    RelayApp().mainloop()
