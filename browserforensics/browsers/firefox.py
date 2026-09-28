"""Extractor for Mozilla Firefox browser.

Extracts: passwords, browsing history, cookies, autofill (form history),
bookmarks, and download records from Firefox profile directories.

Firefox uses its own SQLite schema (moz_* tables) and NSS-based
encryption for passwords.

This module is intended for authorized digital forensics only.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from browserforensics.core.db_handler import SafeSQLiteReader
from browserforensics.core.extractor_base import BrowserExtractor
from browserforensics.decryptors.firefox_decrypt import decrypt_firefox_passwords
from browserforensics.models.data_models import (
    AutofillEntry,
    Bookmark,
    Cookie,
    DownloadEntry,
    HistoryEntry,
    SavedPassword,
)
from browserforensics.utils.time_utils import (
    cookie_expiry_to_datetime,
    firefox_time_to_datetime,
)

logger = logging.getLogger("browserforensics")

# Firefox cookie SameSite values
_FF_SAMESITE_MAP: dict[int, str] = {
    0: "none",
    1: "lax",
    2: "strict",
}


class FirefoxExtractor(BrowserExtractor):
    """Data extractor for Mozilla Firefox.

    Uses places.sqlite, cookies.sqlite, formhistory.sqlite, logins.json,
    and key4.db to extract forensic artifacts from Firefox profiles.
    """

    def __init__(
        self,
        browser_name: str,
        profile_name: str,
        profile_path: Path,
        master_password: str = "",
    ):
        """Initialize the Firefox extractor.

        Args:
            browser_name: Display name (usually 'Firefox').
            profile_name: Profile name (e.g. 'default-release').
            profile_path: Absolute path to the profile directory.
            master_password: Firefox master password (empty if not set).
        """
        super().__init__(browser_name, profile_name, profile_path)
        self.master_password = master_password

    def extract_passwords(self) -> list[SavedPassword]:
        """Extract saved login credentials from logins.json + key4.db.

        Firefox encrypts passwords using NSS (3DES or AES-256). The
        decryptor reads key4.db for the master key and logins.json
        for the encrypted credentials.
        """
        decrypted_logins = decrypt_firefox_passwords(
            self.profile_path, self.master_password
        )

        results: list[SavedPassword] = []
        for login in decrypted_logins:
            # Skip entries with no username and no password
            if not login.get("username") and not login.get("password"):
                continue

            # Firefox logins.json timestamps are in milliseconds since epoch
            date_created = None
            if login.get("date_created"):
                try:
                    date_created = datetime.fromtimestamp(
                        login["date_created"] / 1000.0, tz=timezone.utc
                    )
                except (OSError, ValueError, OverflowError):
                    pass

            date_last_used = None
            if login.get("date_last_used"):
                try:
                    date_last_used = datetime.fromtimestamp(
                        login["date_last_used"] / 1000.0, tz=timezone.utc
                    )
                except (OSError, ValueError, OverflowError):
                    pass

            results.append(
                SavedPassword(
                    browser=self.browser_name,
                    profile=self.profile_name,
                    url=login.get("url", ""),
                    username=login.get("username", ""),
                    password=login.get("password", ""),
                    date_created=date_created,
                    date_last_used=date_last_used,
                )
            )

        return results

    def extract_history(self) -> list[HistoryEntry]:
        """Extract browsing history from places.sqlite.

        History is stored across moz_places (URLs, titles, visit counts)
        and moz_historyvisits (individual visit timestamps). We join them
        and group by place ID to get the last visit time.
        """
        places_db = self.profile_path / "places.sqlite"
        if not places_db.exists():
            return []

        results: list[HistoryEntry] = []

        with SafeSQLiteReader(places_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT p.url, p.title, p.visit_count, "
                    "MAX(h.visit_date) AS last_visit "
                    "FROM moz_places p "
                    "LEFT JOIN moz_historyvisits h ON p.id = h.place_id "
                    "WHERE p.visit_count > 0 "
                    "GROUP BY p.id "
                    "ORDER BY last_visit DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query places.sqlite history: {e}")
                return []

            for row in cursor:
                results.append(
                    HistoryEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        url=row["url"] or "",
                        title=row["title"] or "",
                        visit_count=row["visit_count"] or 0,
                        last_visit_time=firefox_time_to_datetime(
                            row["last_visit"]
                        ),
                    )
                )

        return results

    def extract_cookies(self) -> list[Cookie]:
        """Extract cookies from cookies.sqlite.

        Firefox stores cookies in plaintext (not encrypted) in the
        moz_cookies table. The expiry field is in seconds since epoch.
        """
        cookies_db = self.profile_path / "cookies.sqlite"
        if not cookies_db.exists():
            return []

        results: list[Cookie] = []

        with SafeSQLiteReader(cookies_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT host, name, value, path, expiry, "
                    "isSecure, isHttpOnly, sameSite "
                    "FROM moz_cookies"
                )
            except Exception as e:
                logger.warning(f"Failed to query cookies.sqlite: {e}")
                return []

            for row in cursor:
                results.append(
                    Cookie(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        host=row["host"] or "",
                        name=row["name"] or "",
                        value=row["value"] or "",
                        path=row["path"] or "/",
                        expires=cookie_expiry_to_datetime(row["expiry"]),
                        is_secure=bool(row["isSecure"]),
                        is_httponly=bool(row["isHttpOnly"]),
                        same_site=_FF_SAMESITE_MAP.get(
                            row["sameSite"], "unknown"
                        ),
                    )
                )

        return results

    def extract_autofill(self) -> list[AutofillEntry]:
        """Extract form autofill data from formhistory.sqlite.

        The moz_formhistory table contains form field names, saved values,
        and usage statistics.
        """
        formhistory_db = self.profile_path / "formhistory.sqlite"
        if not formhistory_db.exists():
            return []

        results: list[AutofillEntry] = []

        with SafeSQLiteReader(formhistory_db) as conn:
            try:
                cursor = conn.execute(
                    "SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
                    "FROM moz_formhistory "
                    "ORDER BY timesUsed DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query formhistory.sqlite: {e}")
                return []

            for row in cursor:
                results.append(
                    AutofillEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        field_name=row["fieldname"] or "",
                        value=row["value"] or "",
                        date_created=firefox_time_to_datetime(
                            row["firstUsed"]
                        ),
                        date_last_used=firefox_time_to_datetime(
                            row["lastUsed"]
                        ),
                        use_count=row["timesUsed"] or 0,
                    )
                )

        return results

    def extract_bookmarks(self) -> list[Bookmark]:
        """Extract bookmarks from places.sqlite.

        Bookmarks are stored in moz_bookmarks (tree structure with parent
        references) linked to moz_places (URLs). We build folder paths
        by walking the parent chain.
        """
        places_db = self.profile_path / "places.sqlite"
        if not places_db.exists():
            return []

        results: list[Bookmark] = []

        with SafeSQLiteReader(places_db) as conn:
            # First, build a folder lookup dict: id -> (title, parent_id)
            folder_map: dict[int, tuple[str, int]] = {}
            try:
                folders = conn.execute(
                    "SELECT id, title, parent FROM moz_bookmarks WHERE type = 2"
                )
                for folder in folders:
                    folder_map[folder["id"]] = (
                        folder["title"] or "",
                        folder["parent"],
                    )
            except Exception as e:
                logger.debug(f"Failed to query bookmark folders: {e}")

            # Now extract actual bookmarks (type = 1 = bookmark items)
            try:
                cursor = conn.execute(
                    "SELECT b.title, p.url, b.dateAdded, b.parent "
                    "FROM moz_bookmarks b "
                    "LEFT JOIN moz_places p ON b.fk = p.id "
                    "WHERE b.type = 1 AND p.url IS NOT NULL "
                    "AND p.url NOT LIKE 'place:%' "
                    "ORDER BY b.dateAdded DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query bookmarks: {e}")
                return []

            for row in cursor:
                folder_path = self._build_folder_path(
                    row["parent"], folder_map
                )

                results.append(
                    Bookmark(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        title=row["title"] or "",
                        url=row["url"] or "",
                        folder=folder_path,
                        date_added=firefox_time_to_datetime(
                            row["dateAdded"]
                        ),
                    )
                )

        return results

    def _build_folder_path(
        self,
        parent_id: int,
        folder_map: dict[int, tuple[str, int]],
        max_depth: int = 20,
    ) -> str:
        """Walk the parent chain to build a full folder path.

        Args:
            parent_id: The parent folder ID of a bookmark.
            folder_map: Dict mapping folder ID -> (title, parent_id).
            max_depth: Maximum recursion depth to prevent infinite loops.

        Returns:
            A slash-separated folder path (e.g. 'Bookmarks Menu/Tech').
        """
        parts: list[str] = []
        current_id = parent_id
        depth = 0

        while current_id in folder_map and depth < max_depth:
            title, next_parent = folder_map[current_id]
            if title:  # Skip root nodes with empty titles
                parts.append(title)
            current_id = next_parent
            depth += 1

        parts.reverse()
        return "/".join(parts) if parts else ""

    def extract_downloads(self) -> list[DownloadEntry]:
        """Extract download records from places.sqlite.

        In modern Firefox (v26+), downloads are stored as annotations
        in the moz_annos table linked to moz_places. The
        'downloads/destinationFileURI' annotation holds the file path,
        and 'downloads/metaData' holds JSON with state, size, and timing.
        """
        places_db = self.profile_path / "places.sqlite"
        if not places_db.exists():
            return []

        results: list[DownloadEntry] = []

        with SafeSQLiteReader(places_db) as conn:
            # Check if moz_annos table exists
            try:
                table_check = conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name='moz_annos'"
                ).fetchone()
            except Exception:
                return []

            if not table_check:
                return []

            # Get destination file URIs
            try:
                cursor = conn.execute(
                    "SELECT p.url, a.content, a.place_id, a.dateAdded "
                    "FROM moz_annos a "
                    "JOIN moz_places p ON a.place_id = p.id "
                    "JOIN moz_anno_attributes aa "
                    "    ON a.anno_attribute_id = aa.id "
                    "WHERE aa.name = 'downloads/destinationFileURI' "
                    "ORDER BY a.dateAdded DESC"
                )
            except Exception as e:
                logger.warning(f"Failed to query download annotations: {e}")
                return []

            # Build a map of place_id -> metadata
            metadata_map: dict[int, dict] = {}
            try:
                meta_cursor = conn.execute(
                    "SELECT a.place_id, a.content "
                    "FROM moz_annos a "
                    "JOIN moz_anno_attributes aa "
                    "    ON a.anno_attribute_id = aa.id "
                    "WHERE aa.name = 'downloads/metaData'"
                )
                for meta_row in meta_cursor:
                    try:
                        metadata_map[meta_row["place_id"]] = json.loads(
                            meta_row["content"]
                        )
                    except (json.JSONDecodeError, TypeError):
                        pass
            except Exception:
                pass  # metadata is optional enhancement

            for row in cursor:
                place_id = row["place_id"]
                metadata = metadata_map.get(place_id, {})

                # Parse file path from URI (strip 'file://' prefix)
                target_path = row["content"] or ""
                if target_path.startswith("file:///"):
                    target_path = target_path[8:]  # Remove 'file:///'
                elif target_path.startswith("file://"):
                    target_path = target_path[7:]

                # Parse timing from metadata
                end_time = None
                if metadata.get("endTime"):
                    try:
                        end_time = datetime.fromtimestamp(
                            metadata["endTime"] / 1000.0, tz=timezone.utc
                        )
                    except (OSError, ValueError, OverflowError):
                        pass

                # Download state from metadata
                state_code = metadata.get("state", "")
                state_map = {1: "complete", 2: "failed", 3: "cancelled", 4: "paused"}
                state = state_map.get(state_code, str(state_code) if state_code else "")

                results.append(
                    DownloadEntry(
                        browser=self.browser_name,
                        profile=self.profile_name,
                        url=row["url"] or "",
                        target_path=target_path,
                        total_bytes=metadata.get("fileSize", 0) or 0,
                        start_time=firefox_time_to_datetime(
                            row["dateAdded"]
                        ),
                        end_time=end_time,
                        mime_type="",  # Not stored in annotations
                        state=state,
                    )
                )

        return results
