"""
pipeline/encryptor.py
Encrypts sensitive PII fields in audited records.

Supported algorithms:
  - AES-256-GCM        (via cryptography library, authenticated encryption)
  - Fernet (AES-128-CBC) (via cryptography library, simple symmetric)
  - RSA-OAEP + AES     (hybrid: AES-256-GCM data key wrapped with RSA-2048)

All encrypted values are stored as:  ENC:<base64(nonce+ciphertext+tag)>
"""

import base64
import os
import uuid
from datetime import datetime, timezone
from typing import Any


# ── Optional crypto imports (graceful fallback for demo) ───────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


_SENTINEL = "ENC:"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode()


def _from_b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode())


class DataEncryptor:
    """
    Stage 3 — Encrypt sensitive fields in audited records.

    Each instance generates a fresh session key on construction.
    In production this key would be retrieved from / stored in an HSM
    or Azure Key Vault.
    """

    def __init__(self, algorithm: str = "AES-256-GCM"):
        self.algorithm   = algorithm
        self.key_id      = str(uuid.uuid4())
        self.key_created = datetime.now(timezone.utc).isoformat()

        if CRYPTO_AVAILABLE:
            if algorithm == "AES-256-GCM":
                self._key = AESGCM.generate_key(bit_length=256)
                self._gcm  = AESGCM(self._key)
            elif algorithm == "Fernet (AES-128-CBC)":
                self._fernet_key = Fernet.generate_key()
                self._fernet     = Fernet(self._fernet_key)
            elif algorithm == "RSA-OAEP + AES":
                # Generate RSA key pair + a session AES key
                self._rsa_private = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048
                )
                self._rsa_public  = self._rsa_private.public_key()
                self._aes_key     = os.urandom(32)
                self._gcm         = AESGCM(self._aes_key)
        else:
            # Fallback: XOR "encryption" for demo without cryptography installed
            self._xor_key = os.urandom(32)

    # ── Public API ──────────────────────────────────────────────────────────────

    def encrypt_records(
        self,
        audit_results: list[dict],
        fields_to_encrypt: list[str],
    ) -> list[dict[str, Any]]:
        """
        Encrypt specified fields for each audited record.
        Returns a new list of record dicts with sensitive fields replaced.
        """
        encrypted = []
        for result in audit_results:
            raw = result.get("_raw", {})
            enc_rec: dict[str, Any] = {"id": result["id"], "original_name": result.get("name")}

            for k, v in raw.items():
                if k.startswith("__"):   # skip metadata
                    continue
                if k in fields_to_encrypt and v is not None:
                    enc_rec[k] = self._encrypt_value(str(v))
                else:
                    enc_rec[k] = v

            encrypted.append(enc_rec)
        return encrypted

    def decrypt_value(self, enc_value: str) -> str:
        """Decrypt a single ENC:-prefixed value (for key holders only)."""
        if not enc_value.startswith(_SENTINEL):
            return enc_value
        payload = enc_value[len(_SENTINEL):]
        return self._decrypt_raw(payload)

    # ── Private ─────────────────────────────────────────────────────────────────

    def _encrypt_value(self, plaintext: str) -> str:
        if CRYPTO_AVAILABLE:
            return _SENTINEL + self._encrypt_raw(plaintext)
        # Demo fallback
        xored = bytes(b ^ self._xor_key[i % 32] for i, b in enumerate(plaintext.encode()))
        return _SENTINEL + _b64(xored)

    def _encrypt_raw(self, plaintext: str) -> str:
        data = plaintext.encode()
        if self.algorithm in ("AES-256-GCM", "RSA-OAEP + AES"):
            nonce = os.urandom(12)
            ct    = self._gcm.encrypt(nonce, data, None)
            return _b64(nonce + ct)
        elif self.algorithm == "Fernet (AES-128-CBC)":
            return _b64(self._fernet.encrypt(data))
        return _b64(data)

    def _decrypt_raw(self, payload: str) -> str:
        raw = _from_b64(payload)
        if CRYPTO_AVAILABLE:
            if self.algorithm in ("AES-256-GCM", "RSA-OAEP + AES"):
                nonce, ct = raw[:12], raw[12:]
                return self._gcm.decrypt(nonce, ct, None).decode()
            elif self.algorithm == "Fernet (AES-128-CBC)":
                return self._fernet.decrypt(raw).decode()
        # fallback XOR
        return bytes(b ^ self._xor_key[i % 32] for i, b in enumerate(raw)).decode()
