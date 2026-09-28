"""Pure-Python Firefox password decryption.

Supports both legacy (3DES-CBC with SHA1) and modern (AES-256-CBC with
PBKDF2/SHA256) Firefox password encryption schemes, without requiring
the Mozilla NSS shared library.

Based on the approach from firepwd by Laurent Clevy.

This module is intended for authorized digital forensics only.
"""

import hashlib
import hmac
import json
import logging
import sqlite3
from base64 import b64decode
from pathlib import Path

from pyasn1.codec.der import decoder as asn1_decoder  # type: ignore[import-untyped]
from pyasn1.type import univ as asn1_univ  # type: ignore[import-untyped]
from Crypto.Cipher import DES3, AES  # type: ignore[import-untyped]
from Crypto.Protocol.KDF import PBKDF2  # type: ignore[import-untyped]
from Crypto.Hash import SHA256, HMAC as CryptoHMAC  # type: ignore[import-untyped]

logger = logging.getLogger("browserforensics")

# ASN.1 OIDs used in Firefox crypto structures
_OID_PKCS5_PBES2 = "1.2.840.113549.1.5.13"
_OID_PKCS5_PBKDF2 = "1.2.840.113549.1.5.12"
_OID_AES256_CBC = "2.16.840.1.101.3.4.1.42"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_HMAC_SHA256 = "1.2.840.113549.2.9"
_OID_DES_EDE3_CBC = "1.2.840.113549.3.7"
_OID_PKCS12_PBE_SHA1_3DES = "1.2.840.113549.1.12.5.1.3"


def _remove_pkcs7_padding(data: bytes) -> bytes:
    """Remove PKCS#7 padding from decrypted data."""
    if not data:
        return data
    pad_len = data[-1]
    if isinstance(pad_len, int) and 1 <= pad_len <= len(data):
        if all(b == pad_len for b in data[-pad_len:]):
            return data[:-pad_len]
    return data


def _decrypt_3des_pbe(
    global_salt: bytes,
    master_password: str,
    entry_salt: bytes,
    encrypted_data: bytes,
) -> bytes:
    """Decrypt data using PKCS#12 PBE with SHA1 and 3DES-CBC.

    This is the legacy Firefox encryption scheme (pre-Firefox 58).
    Key derivation uses a combination of SHA1 and HMAC-SHA1.

    Args:
        global_salt: The global salt from key4.db metadata table.
        master_password: The user's master password (empty string if not set).
        entry_salt: The per-entry salt from the ASN.1 structure.
        encrypted_data: The ciphertext to decrypt.

    Returns:
        The decrypted plaintext bytes.
    """
    hp = hashlib.sha1(global_salt + master_password.encode("utf-8")).digest()

    # Pad entry_salt to 20 bytes
    pes = entry_salt + b"\x00" * (20 - len(entry_salt))

    chp = hashlib.sha1(hp + entry_salt).digest()

    k1 = hmac.new(chp, pes + entry_salt, hashlib.sha1).digest()
    tk = hmac.new(chp, pes, hashlib.sha1).digest()
    k2 = hmac.new(chp, tk + entry_salt, hashlib.sha1).digest()

    k = k1 + k2  # 40 bytes
    iv = k[-8:]  # Last 8 bytes as IV
    key = k[:24]  # First 24 bytes as 3DES key

    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return _remove_pkcs7_padding(cipher.decrypt(encrypted_data))


def _decrypt_aes256_cbc(
    global_salt: bytes,
    master_password: str,
    entry_salt: bytes,
    iteration_count: int,
    iv: bytes,
    encrypted_data: bytes,
) -> bytes:
    """Decrypt data using PBKDF2 + AES-256-CBC.

    This is the modern Firefox encryption scheme (Firefox 58+).

    Args:
        global_salt: The global salt from key4.db metadata table.
        master_password: The user's master password.
        entry_salt: PBKDF2 salt from the ASN.1 structure.
        iteration_count: PBKDF2 iteration count.
        iv: AES-CBC initialization vector.
        encrypted_data: The ciphertext to decrypt.

    Returns:
        The decrypted plaintext bytes.
    """
    # First derive the password input: SHA256(global_salt + master_password)
    password = hashlib.sha256(
        global_salt + master_password.encode("utf-8")
    ).digest()

    # Then run PBKDF2 with SHA256
    key = PBKDF2(
        password,
        entry_salt,
        dkLen=32,
        count=iteration_count,
        prf=lambda p, s: CryptoHMAC.new(p, s, SHA256).digest(),
    )

    cipher = AES.new(key, AES.MODE_CBC, iv)
    return _remove_pkcs7_padding(cipher.decrypt(encrypted_data))


def _parse_asn1_private_key(
    a11_data: bytes,
) -> dict:
    """Parse the ASN.1 structure from key4.db nssPrivate.a11 column.

    The structure contains the encryption algorithm parameters and the
    encrypted master key.

    Args:
        a11_data: Raw bytes from the a11 column.

    Returns:
        Dict with keys: 'algorithm' ('3des' or 'aes256'), 'entry_salt',
        'encrypted_data', and for aes256: 'iteration_count', 'iv'.
    """
    decoded, _ = asn1_decoder.decode(a11_data)

    # Get the algorithm OID
    algo_seq = decoded[0]
    algo_oid = str(algo_seq[0])

    if algo_oid == _OID_PKCS12_PBE_SHA1_3DES:
        # Legacy: PKCS#12 PBE with SHA1 and 3DES-CBC
        params = algo_seq[1]
        entry_salt = bytes(params[0])
        # iteration_count is in params[1] but not used for this algorithm
        encrypted_data = bytes(decoded[1])

        return {
            "algorithm": "3des",
            "entry_salt": entry_salt,
            "encrypted_data": encrypted_data,
        }

    elif algo_oid == _OID_PKCS5_PBES2:
        # Modern: PBES2 with PBKDF2 + AES-256-CBC
        pbes2_params = algo_seq[1]

        # PBKDF2 parameters
        kdf_seq = pbes2_params[0]
        kdf_oid = str(kdf_seq[0])
        if kdf_oid != _OID_PKCS5_PBKDF2:
            raise ValueError(f"Expected PBKDF2 OID, got: {kdf_oid}")

        kdf_params = kdf_seq[1]
        entry_salt = bytes(kdf_params[0])
        iteration_count = int(kdf_params[1])

        # AES-256-CBC parameters
        enc_seq = pbes2_params[1]
        enc_oid = str(enc_seq[0])
        if enc_oid != _OID_AES256_CBC:
            logger.warning(f"Unexpected encryption OID: {enc_oid}")

        iv = bytes(enc_seq[1])
        encrypted_data = bytes(decoded[1])

        return {
            "algorithm": "aes256",
            "entry_salt": entry_salt,
            "iteration_count": iteration_count,
            "iv": iv,
            "encrypted_data": encrypted_data,
        }

    else:
        raise ValueError(f"Unknown encryption algorithm OID: {algo_oid}")


def get_firefox_master_key(
    profile_path: Path, master_password: str = ""
) -> bytes | None:
    """Extract and decrypt the Firefox master key from key4.db.

    Steps:
    1. Read global_salt and check value from metadata table
    2. Read encrypted private key from nssPrivate table
    3. Parse ASN.1 structure to determine encryption scheme
    4. Decrypt the master key using the appropriate algorithm
    5. Verify by checking the decrypted check value

    Args:
        profile_path: Path to the Firefox profile directory.
        master_password: Firefox master password (empty if not set).

    Returns:
        The decrypted master key (typically 24 bytes for 3DES), or None.
    """
    key4_path = profile_path / "key4.db"
    if not key4_path.exists():
        logger.warning(f"key4.db not found in {profile_path}")
        return None

    try:
        conn = sqlite3.connect(str(key4_path))
        conn.row_factory = sqlite3.Row

        # Read global salt and check value from metadata
        try:
            meta_row = conn.execute(
                "SELECT item1, item2 FROM metadata WHERE id = 'password'"
            ).fetchone()
        except sqlite3.OperationalError:
            logger.warning("metadata table not found in key4.db")
            conn.close()
            return None

        if meta_row is None:
            logger.warning("No password metadata found in key4.db")
            conn.close()
            return None

        global_salt = bytes(meta_row["item1"])
        check_value_encrypted = bytes(meta_row["item2"])

        # Read encrypted private key from nssPrivate
        try:
            nss_row = conn.execute(
                "SELECT a11, a102 FROM nssPrivate"
            ).fetchone()
        except sqlite3.OperationalError:
            logger.warning("nssPrivate table not found in key4.db")
            conn.close()
            return None

        conn.close()

        if nss_row is None:
            logger.warning("No private key found in key4.db")
            return None

        a11_data = bytes(nss_row["a11"])

        # Parse the ASN.1 structure to determine encryption scheme
        parsed = _parse_asn1_private_key(a11_data)

        # Decrypt the master key
        if parsed["algorithm"] == "3des":
            master_key = _decrypt_3des_pbe(
                global_salt,
                master_password,
                parsed["entry_salt"],
                parsed["encrypted_data"],
            )
        elif parsed["algorithm"] == "aes256":
            master_key = _decrypt_aes256_cbc(
                global_salt,
                master_password,
                parsed["entry_salt"],
                parsed["iteration_count"],
                parsed["iv"],
                parsed["encrypted_data"],
            )
        else:
            logger.error(f"Unknown algorithm: {parsed['algorithm']}")
            return None

        # Verify the master key by decrypting the check value
        try:
            check_parsed = _parse_asn1_private_key(check_value_encrypted)
            if check_parsed["algorithm"] == "3des":
                check_result = _decrypt_3des_pbe(
                    global_salt,
                    master_password,
                    check_parsed["entry_salt"],
                    check_parsed["encrypted_data"],
                )
            elif check_parsed["algorithm"] == "aes256":
                check_result = _decrypt_aes256_cbc(
                    global_salt,
                    master_password,
                    check_parsed["entry_salt"],
                    check_parsed["iteration_count"],
                    check_parsed["iv"],
                    check_parsed["encrypted_data"],
                )
            else:
                check_result = b""

            expected = b"password-check\x02\x02"
            if check_result != expected:
                logger.warning(
                    "Master password verification failed. "
                    "The master password may be incorrect."
                )
                # Still return the key — it might partially work for some entries
        except Exception as e:
            logger.debug(f"Check value verification failed: {e}")

        logger.debug("Successfully decrypted Firefox master key")
        return master_key

    except Exception as e:
        logger.error(f"Failed to extract Firefox master key: {e}")
        return None


def _decrypt_login_field(encrypted_b64: str, master_key: bytes) -> str:
    """Decrypt a single encrypted field from logins.json.

    Each encrypted field is a base64-encoded ASN.1 DER structure:
    SEQUENCE {
        SEQUENCE {
            OID (1.2.840.113549.3.7 = DES-EDE3-CBC)
            SEQUENCE {
                OCTET STRING (key_id / entry_salt — unused for login decryption)
                OCTET STRING (IV)
            }
        }
        OCTET STRING (encrypted_data)
    }

    Args:
        encrypted_b64: Base64-encoded encrypted field value.
        master_key: The decrypted master key from key4.db.

    Returns:
        The decrypted plaintext string.
    """
    try:
        raw = b64decode(encrypted_b64)
        decoded, _ = asn1_decoder.decode(raw)

        algo_seq = decoded[0]
        algo_oid = str(algo_seq[0])

        if algo_oid == _OID_DES_EDE3_CBC:
            # 3DES-CBC decryption
            params = algo_seq[1]
            iv = bytes(params[1]) if len(params) > 1 else bytes(params[0])
            encrypted_data = bytes(decoded[1])

            # Use first 24 bytes of master_key for 3DES
            key = master_key[:24]
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            decrypted = _remove_pkcs7_padding(cipher.decrypt(encrypted_data))
            return decrypted.decode("utf-8", errors="replace")

        elif algo_oid == _OID_AES256_CBC:
            # AES-256-CBC decryption
            iv = bytes(algo_seq[1])
            encrypted_data = bytes(decoded[1])

            key = master_key[:32]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = _remove_pkcs7_padding(cipher.decrypt(encrypted_data))
            return decrypted.decode("utf-8", errors="replace")

        else:
            logger.debug(f"Unknown login encryption OID: {algo_oid}")
            return "[unknown encryption]"

    except Exception as e:
        logger.debug(f"Login field decryption failed: {e}")
        return "[decryption failed]"


def decrypt_firefox_passwords(
    profile_path: Path, master_password: str = ""
) -> list[dict]:
    """Decrypt all saved passwords from a Firefox profile.

    Reads the master key from key4.db and uses it to decrypt the
    credentials stored in logins.json.

    Args:
        profile_path: Path to the Firefox profile directory.
        master_password: Firefox master password (empty if not set).

    Returns:
        List of dicts with keys: url, username, password, date_created,
        date_last_used (timestamps in milliseconds since epoch).
    """
    logins_path = profile_path / "logins.json"
    if not logins_path.exists():
        logger.debug(f"logins.json not found in {profile_path}")
        return []

    master_key = get_firefox_master_key(profile_path, master_password)
    if master_key is None:
        logger.warning("Cannot decrypt Firefox passwords without master key")
        return []

    try:
        with open(logins_path, "r", encoding="utf-8") as f:
            logins_data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read logins.json: {e}")
        return []

    results = []
    logins = logins_data.get("logins", [])
    logger.debug(f"Found {len(logins)} login entries in logins.json")

    for login in logins:
        try:
            encrypted_username = login.get("encryptedUsername", "")
            encrypted_password = login.get("encryptedPassword", "")

            username = (
                _decrypt_login_field(encrypted_username, master_key)
                if encrypted_username
                else ""
            )
            password = (
                _decrypt_login_field(encrypted_password, master_key)
                if encrypted_password
                else ""
            )

            results.append(
                {
                    "url": login.get("hostname", login.get("origin", "")),
                    "username": username,
                    "password": password,
                    "date_created": login.get("timeCreated"),
                    "date_last_used": login.get("timeLastUsed"),
                }
            )
        except Exception as e:
            logger.debug(f"Failed to decrypt login entry: {e}")
            continue

    logger.debug(f"Successfully decrypted {len(results)} login entries")
    return results
