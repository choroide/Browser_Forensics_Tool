"""Chromium credential decryption for macOS (Keychain + PBKDF2 + AES-128-CBC).

On macOS, Chromium retrieves its Safe Storage password from the macOS Keychain,
then derives an AES-128 key via PBKDF2 with salt 'saltysalt' and 1003 iterations.
Decryption uses AES-128-CBC with an IV of 16 space characters (0x20).

If the Keychain password cannot be retrieved, falls back to 'peanuts'.

This module is intended for authorized digital forensics only.
"""

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("browserforensics")

# Maps browser display names to their Keychain service/account entries
_KEYCHAIN_MAP: dict[str, tuple[str, str]] = {
    "Google Chrome": ("Chrome Safe Storage", "Chrome"),
    "Chromium": ("Chromium Safe Storage", "Chromium"),
    "Microsoft Edge": ("Microsoft Edge Safe Storage", "Microsoft Edge"),
    "Brave": ("Brave Safe Storage", "Brave"),
    "Opera": ("Opera Safe Storage", "Opera"),
    "Vivaldi": ("Vivaldi Safe Storage", "Vivaldi"),
}


def _get_keychain_password(browser_name: str) -> str:
    """Retrieve the browser's Safe Storage password from macOS Keychain.

    Args:
        browser_name: Display name of the browser (e.g. 'Google Chrome').

    Returns:
        The Keychain password string, or 'peanuts' as fallback.
    """
    service, account = _KEYCHAIN_MAP.get(
        browser_name, ("Chrome Safe Storage", "Chrome")
    )

    try:
        result = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-w",
                "-s",
                service,
                "-a",
                account,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            logger.debug(f"Retrieved Keychain password for {browser_name}")
            return result.stdout.strip()
    except FileNotFoundError:
        logger.debug("'security' command not found — not on macOS?")
    except subprocess.TimeoutExpired:
        logger.debug("Keychain lookup timed out")
    except Exception as e:
        logger.debug(f"Keychain lookup failed: {e}")

    logger.debug(f"Falling back to default password for {browser_name}")
    return "peanuts"


def get_master_key(
    local_state_path: Path, browser_name: str = "Google Chrome"
) -> bytes | None:
    """Derive the AES-128 key from the Keychain password via PBKDF2.

    PBKDF2(password=keychain_password, salt=b'saltysalt',
           iterations=1003, dkLen=16)

    Args:
        local_state_path: Path to Local State (unused on macOS).
        browser_name: Browser name for Keychain lookup.

    Returns:
        The derived 16-byte AES key, or None on failure.
    """
    try:
        from Crypto.Protocol.KDF import PBKDF2  # type: ignore[import-untyped]

        password = _get_keychain_password(browser_name)
        key = PBKDF2(password, b"saltysalt", dkLen=16, count=1003)
        logger.debug(f"Derived Chromium master key via PBKDF2 (macOS)")
        return key
    except Exception as e:
        logger.error(f"Failed to derive master key: {e}")
        return None


def decrypt_value(encrypted_value: bytes, master_key: bytes | None) -> str:
    """Decrypt an AES-128-CBC encrypted Chromium value on macOS.

    Same encryption scheme as Linux: b'v10'/'v11' prefix + AES-CBC + PKCS7.

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

            iv = b" " * 16
            cipher = AES.new(master_key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted_value[3:])

            # Remove PKCS7 padding
            padding_len = decrypted[-1]
            if isinstance(padding_len, int) and 1 <= padding_len <= 16:
                if all(b == padding_len for b in decrypted[-padding_len:]):
                    decrypted = decrypted[:-padding_len]

            return decrypted.decode("utf-8", errors="replace")

        return ""
    except Exception as e:
        logger.debug(f"Value decryption failed: {e}")
        return "[decryption failed]"
