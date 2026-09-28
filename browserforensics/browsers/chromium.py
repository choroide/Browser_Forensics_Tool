"""Extractor for all Chromium-based browsers.

Supports: Google Chrome, Microsoft Edge, Brave, Opera, Vivaldi, Chromium.
All share the same SQLite schema — only the profile path differs.

Extracts: passwords, browsing history, cookies, autofill data,
bookmarks, and download records.

This module is intended for authorized digital forensics only.
"""

import json
import logging
import platform
from pathlib import Path

from browserforensics.core.db_handler import SafeSQLiteReader
from browserforensics.core.extractor_base import BrowserExtractor
from browserforensics.models.data_models import (
    AutofillEntry,
    Bookmark,
    Cookie,
    DownloadEntry,
    HistoryEntry,
    SavedPassword,
)
from browserforensics.utils.time_utils import chromium_time_to_datetime

logger = logging.getLogger("browserforensics")

# Chromium download state codes
_DOWNLOAD_STATES: dict[int, str] = {
    0: "in_progress",
    1: "complete",
    2: "cancelled",
    3: "interrupted",
    4: "interrupted",
}

# Chromium cookie SameSite values
_SAMESITE_MAP: dict[int, str] = {
    -1: "unspecified",
    0: "no_restriction",
    1: "lax",
    2: "strict",
}


class ChromiumExtractor(BrowserExtractor):
    """Data extractor for Chromium-based browsers.

    Uses SQLite databases and JSON files in the browser's profile directory
    to extract forensic artifacts. Passwords and cookie values are decrypted
    using the platform-specific decryptor module.
    """

    def __init__(
        self,
        browser_name: str,
        profile_name: str,
        profile_path: Path,
        user_data_path: Path | None = None,
    ):
        """Initialize the Chromium extractor.

        Args:
            browser_name: Display name (e.g. 'Google Chrome').
            profile_name: Profile directory name (e.g. 'Default').
            profile_path: Absolute path to the profile directory.
            user_data_path: Parent User Data directory (contains Local State).
        """
        super().__init__(browser_name, profile_name, profile_path)
        self.user_data_path = user_data_path or profile_path.parent
        self._master_key: bytes | None = None
        self._master_key_loaded = False

    def _get_master_key(self) -> bytes | None:
        """Lazily load and cache the decrypted master encryption key.

        The master key is stored in the 'Local State' JSON file and
        encrypted with an OS-specific mechanism.
        """
        if self._master_key_loaded:
            return self._master_key

        self._master_key_loaded = True

        # Find Local State file
        local_state_path = self.user_data_path / "Local State"
        if not local_state_path.exists():
            # Opera stores Local State in the profile directory itself
            local_state_path = self.profile_path / "Local State"
        if not local_state_path.exists():
            logger.warning(
                f"Local State not found for {self.browser_name}"
            )
            return None

        system = platform.system()
        try:
            match system:
                case "Windows":
                    from browserforensics.decryptors.chromium_windows import (
                        get_master_key,
                    )

                    self._master_key = get_master_key(local_state_path)

                case "Linux":
                    from browserforensics.decryptors.chromium_linux import (
                        get_master_key,
                    )

                    self._master_key = get_master_key(local_state_path)

                case "Darwin":
                    from browserforensics.decryptors.chromium_macos import (
                        get_master_key,
                    )

                    self._master_key = get_master_key(
                        local_state_path, self.browser_name
                    )

                case _:
                    logger.warning(
                        f"Unsupported platform for decryption: {system}"
                    )

        except Exception as e:
            logger.error(f"Failed to load master key: {e}")

        return self._master_key

    def _decrypt(self, encrypted_value: bytes) -> str:
        """Decrypt an encrypted value using the platform-appropriate decryptor.

        Args:
            encrypted_value: Raw encrypted bytes from a SQLite column.

        Returns:
            Decrypted plaintext string.
        """
        if not encrypted_value:
            return ""

        system = platform.system()
        try:
            match system:
                case "Windows":
                    from browserforensics.decryptors.chromium_windows import (
                        decrypt_value,
                    )
                case "Linux":
                    from browserforensics.decryptors.chromium_linux import (
                        decrypt_value,
                    )
                case "Darwin":
                    from browserforensics.decryptors.chromium_macos import (
                        decrypt_value,
                    )
                case _:
                    return "[unsupported platform]"

            return decrypt_value(encrypted_value, self._get_master_key())

        except Exception as e:
            logger.debug(f"Decryption error: {e}")
            return "[decryption failed]"

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def extract_passwords(self) -> list[SavedPassword]:
        """Extract saved login credentials from 'Login Data' SQLite DB.

        Passwords are AES-GCM encrypted (v80+) or DPAPI encrypted (legacy).
        Each row in the 'logins' table represents one saved credential.
        """
        login_db = self.profile_path / "Login Data"
        if not login_db.exists():
            return []

        results: list[SavedPassword] = []

        with SafeSQLiteReader(login_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT origin_url, username_value, password_value, "
                    "date_created, date_last_used "
                    "FROM logins ORDER BY date_created DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query Login Data: {e}")
                return []

            for row in cursor:
                password = self._decrypt(row["password_value"])

                # Skip entries with no username and no password
                if not row["username_value"] and not password:
                    continue

                results.append(
                    SavedPassword(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        url=row["origin_url"] or "",
                        username=row["username_value"] or "",
                        password=password,
                        date_created=chromium_time_to_datetime(
                            row["date_created"]
                        ),
                        date_last_used=chromium_time_to_datetime(
                            row["date_last_used"]
                        ),
                    )
                )

        return results

    def extract_history(self) -> list[HistoryEntry]:
        """Extract browsing history from 'History' SQLite DB.

        The 'urls' table contains URL entries with visit counts and
        last visit timestamps in Chromium time format.
        """
        history_db = self.profile_path / "History"
        if not history_db.exists():
            return []

        results: list[HistoryEntry] = []

        with SafeSQLiteReader(history_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT url, title, visit_count, last_visit_time "
                    "FROM urls ORDER BY last_visit_time DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query History: {e}")
                return []

            for row in cursor:
                results.append(
                    HistoryEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_count=row["visit_count"] or 0,
                        last_visit_time=chromium_time_to_datetime(
                            row["last_visit_time"]
                        ),
                    )
                )

        return results

    def extract_cookies(self) -> list[Cookie]:
        """Extract cookies from 'Cookies' SQLite DB.

        Cookie values are encrypted the same way as passwords (AES-GCM on
        v80+). Both encrypted_value and plaintext value columns are checked.
        """
        cookies_db = self.profile_path / "Cookies"
        if not cookies_db.exists():
            return []

        results: list[Cookie] = []

        with SafeSQLiteReader(cookies_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT host_key, name, encrypted_value, value, path, "
                    "expires_utc, is_secure, is_httponly, samesite "
                    "FROM cookies"
                )
            except Exception as e:
                logger.warning(f"Failed to query Cookies: {e}")
                return []

            for row in cursor:
                # Prefer decrypted encrypted_value, fall back to plaintext
                value = ""
                if row["encrypted_value"]:
                    value = self._decrypt(row["encrypted_value"])
                if not value and row["value"]:
                    value = row["value"]

                results.append(
                    Cookie(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        host=row["host_key"] or "",
                        name=row["name"] or "",
                        value=value,
                        path=row["path"] or "/",
                        expires=chromium_time_to_datetime(
                            row["expires_utc"]
                        ),
                        is_secure=bool(row["is_secure"]),
                        is_httponly=bool(row["is_httponly"]),
                        same_site=_SAMESITE_MAP.get(
                            row["samesite"], "unknown"
                        ),
                    )
                )

        return results

    def extract_autofill(self) -> list[AutofillEntry]:
        """Extract autofill form data from 'Web Data' SQLite DB.

        The 'autofill' table contains form field names, values, and
        usage counts with timestamps.
        """
        webdata_db = self.profile_path / "Web Data"
        if not webdata_db.exists():
            return []

        results: list[AutofillEntry] = []

        with SafeSQLiteReader(webdata_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT name, value, count, date_created, date_last_used "
                    "FROM autofill ORDER BY count DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query Web Data (autofill): {e}")
                return []

            for row in cursor:
                results.append(
                    AutofillEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        field_name=row["name"] or "",
                        value=row["value"] or "",
                        date_created=chromium_time_to_datetime(
                            row["date_created"]
                        ),
                        date_last_used=chromium_time_to_datetime(
                            row["date_last_used"]
                        ),
                        use_count=row["count"] or 0,
                    )
                )

        return results

    def extract_bookmarks(self) -> list[Bookmark]:
        """Extract bookmarks from the 'Bookmarks' JSON file.

        Chromium stores bookmarks in a JSON tree structure with roots:
        bookmark_bar, other, and synced.
        """
        bookmarks_file = self.profile_path / "Bookmarks"
        if not bookmarks_file.exists():
            return []

        try:
            with open(bookmarks_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read Bookmarks: {e}")
            return []

        results: list[Bookmark] = []
        roots = data.get("roots", {})

        for root_name in ("bookmark_bar", "other", "synced"):
            root_node = roots.get(root_name)
            if root_node:
                folder_label = root_name.replace("_", " ").title()
                results.extend(
                    self._parse_bookmarks_tree(root_node, folder_label)
                )

        return results

    def _parse_bookmarks_tree(
        self, node: dict, folder: str = ""
    ) -> list[Bookmark]:
        """Recursively walk a Chromium bookmarks tree node.

        Args:
            node: A bookmark tree node dict.
            folder: Current folder path for context.

        Returns:
            Flat list of Bookmark entries.
        """
        results: list[Bookmark] = []
        node_type = node.get("type", "")

        if node_type == "url":
            date_added_raw = node.get("date_added")
            date_added = None
            if date_added_raw:
                try:
                    date_added = chromium_time_to_datetime(int(date_added_raw))
                except (ValueError, TypeError):
                    pass

            results.append(
                Bookmark(
                    browser=self.browser_name,
                    profile=self.profile_name,
                    title=node.get("name", ""),
                    url=node.get("url", ""),
                    folder=folder,
                    date_added=date_added,
                )
            )

        elif node_type == "folder":
            children = node.get("children", [])
            folder_name = node.get("name", "Unknown")
            child_folder = f"{folder}/{folder_name}" if folder else folder_name

            for child in children:
                results.extend(
                    self._parse_bookmarks_tree(child, child_folder)
                )

        return results

    def extract_downloads(self) -> list[DownloadEntry]:
        """Extract download records from 'History' SQLite DB.

        The 'downloads' table in the History database contains download
        URLs, file paths, sizes, and completion states.
        """
        history_db = self.profile_path / "History"
        if not history_db.exists():
            return []

        results: list[DownloadEntry] = []

        with SafeSQLiteReader(history_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT tab_url, target_path, total_bytes, "
                    "start_time, end_time, mime_type, state "
                    "FROM downloads ORDER BY start_time DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query downloads: {e}")
                return []

            for row in cursor:
                state_code = row["state"]
                state_str = _DOWNLOAD_STATES.get(
                    state_code,
                    f"unknown ({state_code})" if state_code else "",
                )

                results.append(
                    DownloadEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        url=row["tab_url"] or "",
                        target_path=row["target_path"] or "",
                        total_bytes=row["total_bytes"] or 0,
                        start_time=chromium_time_to_datetime(
                            row["start_time"]
                        ),
                        end_time=chromium_time_to_datetime(row["end_time"]),
                        mime_type=row["mime_type"] or "",
                        state=state_str,
                    )
                )

        return results
