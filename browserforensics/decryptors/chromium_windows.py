"""Chromium credential decryption for Windows (DPAPI + AES-GCM).

Chromium v80+ encrypts passwords and cookies with AES-256-GCM, using a
master key that is itself encrypted with the Windows Data Protection API
(DPAPI). The encrypted master key is stored in the browser's 'Local State'
JSON file under os_crypt.encrypted_key.

This module is intended for authorized digital forensics only.
"""

import base64
import json
import logging
from pathlib import Path

logger = logging.getLogger("browserforensics")


def get_master_key(local_state_path: Path) -> bytes | None:
    """Extract and decrypt the AES master key from Local State.

    The key in Local State is: base64(b'DPAPI' + DPAPI_encrypted_aes_key).
    We strip the 5-byte 'DPAPI' prefix, then call CryptUnprotectData.

    Args:
        local_state_path: Path to the browser's Local State JSON file.

    Returns:
        The decrypted AES-256 master key, or None on failure.
    """
    try:
        import win32crypt  # type: ignore[import-untyped]
    except ImportError:
        logger.error(
            "pywin32 is required on Windows for credential decryption. "
            "Install with: pip install pywin32"
        )
        return None

    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)

        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)

        # Strip the b'DPAPI' prefix (first 5 bytes)
        encrypted_key = encrypted_key[5:]

        # Decrypt using Windows DPAPI — requires same user context
        master_key = win32crypt.CryptUnprotectData(
            encrypted_key, None, None, None, 0
        )[1]
        logger.debug("Successfully decrypted Chromium master key via DPAPI")
        return master_key

    except KeyError:
        logger.error("os_crypt.encrypted_key not found in Local State")
        return None
    except Exception as e:
        logger.error(f"Failed to extract master key: {e}")
        return None


def decrypt_value(encrypted_value: bytes, master_key: bytes | None) -> str:
    """Decrypt a Chromium v80+ AES-GCM encrypted value.

    Encrypted format: b'v10' or b'v11' + nonce(12 bytes) + ciphertext + tag(16 bytes)

    Pre-v80 values use raw DPAPI encryption (no version prefix).

    Args:
        encrypted_value: The raw encrypted bytes from the SQLite database.
        master_key: The decrypted AES master key.

    Returns:
        The decrypted plaintext string, or an error placeholder.
    """
    if not encrypted_value:
        return ""

    try:
        # Chromium v80+ AES-256-GCM encryption
        if encrypted_value[:3] in (b"v10", b"v11"):
            if master_key is None:
                return "[decryption key unavailable]"

            from Crypto.Cipher import AES  # type: ignore[import-untyped]

            nonce = encrypted_value[3:15]  # 12-byte nonce
            ciphertext_with_tag = encrypted_value[15:]

            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            # GCM tag is the last 16 bytes
            ciphertext = ciphertext_with_tag[:-16]
            tag = ciphertext_with_tag[-16:]
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode("utf-8", errors="replace")

        else:
            # Legacy DPAPI-only encryption (pre-v80)
            try:
                import win32crypt  # type: ignore[import-untyped]

                decrypted = win32crypt.CryptUnprotectData(
                    encrypted_value, None, None, None, 0
                )[1]
                return decrypted.decode("utf-8", errors="replace")
            except ImportError:
                return "[pywin32 required for legacy decryption]"

    except Exception as e:
        logger.debug(f"Value decryption failed: {e}")
        return "[decryption failed]"
