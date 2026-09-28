"""Chromium credential decryption for Linux (PBKDF2 + AES-128-CBC).

On Linux, Chromium derives its encryption key from the hardcoded password
'peanuts' (when no keyring integration is available) using PBKDF2 with salt
'saltysalt' and 1 iteration. The resulting 16-byte key is used for
AES-128-CBC decryption with an IV of 16 space characters (0x20).

This module is intended for authorized digital forensics only.
"""

import logging
from pathlib import Path

logger = logging.getLogger("browserforensics")


def get_master_key(local_state_path: Path) -> bytes | None:
    """Derive the AES-128 key from the hardcoded password 'peanuts'.

    Linux Chromium uses PBKDF2(password='peanuts', salt=b'saltysalt',
    iterations=1, dkLen=16) when the system keyring is not available.

    Args:
        local_state_path: Path to Local State (unused on Linux, kept for
            interface compatibility with other platform decryptors).

    Returns:
        The derived 16-byte AES key, or None on failure.
    """
    try:
        from Crypto.Protocol.KDF import PBKDF2  # type: ignore[import-untyped]

        key = PBKDF2("peanuts", b"saltysalt", dkLen=16, count=1)
        logger.debug("Derived Chromium master key via PBKDF2 (Linux)")
        return key
    except Exception as e:
        logger.error(f"Failed to derive master key: {e}")
        return None


def decrypt_value(encrypted_value: bytes, master_key: bytes | None) -> str:
    """Decrypt an AES-128-CBC encrypted Chromium value on Linux.

    Encrypted format: b'v10' or b'v11' + AES-CBC-ciphertext (PKCS7 padded).
    IV is 16 space characters (0x20).

    Args:
        encrypted_value: The raw encrypted bytes from the SQLite database.
        master_key: The derived 16-byte AES key.

    Returns:
        The decrypted plaintext string, or an error placeholder.
    """
    if not encrypted_value:
        return ""

    try:
        if encrypted_value[:3] in (b"v10", b"v11"):
            if master_key is None:
                return "[decryption key unavailable]"

            from Crypto.Cipher import AES  # type: ignore[import-untyped]

            iv = b" " * 16  # 16 space characters
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_value[3:])

            # Remove PKCS7 padding
            padding_len = decrypted[-1]
            if isinstance(padding_len, int) and 1 <= padding_len <= 16:
                # Validate padding bytes are all the same value
                if all(b == padding_len for b in decrypted[-padding_len:]):
                    decrypted = decrypted[:-padding_len]

            return decrypted.decode("utf-8", errors="replace")

        return ""
    except Exception as e:
        logger.debug(f"Value decryption failed: {e}")
        return "[decryption failed]"
