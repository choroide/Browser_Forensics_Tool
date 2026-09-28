"""Data models for extracted browser artifacts."""

from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class SavedPassword:
    browser: str
    profile: str
    url: str
    username: str
    password: str
    date_created: datetime | None
    date_last_used: datetime | None

@dataclass
class HistoryEntry:
    browser: str
    profile: str
    url: str
    title: str
    visit_count: int
    last_visit_time: datetime | None

@dataclass
class Cookie:
    browser: str
    profile: str
    host: str
    name: str
    value: str
    path: str = "/"
    expires: datetime | None = None
    is_secure: bool = False
    is_httponly: bool = False
    same_site: str = ""

@dataclass
class AutofillEntry:
    browser: str
    profile: str
    field_name: str
    value: str
    date_created: datetime | None
    date_last_used: datetime | None
    use_count: int = 0

@dataclass
class Bookmark:
    browser: str
    profile: str
    title: str
    url: str
    folder: str = ""
    date_added: datetime | None = None

@dataclass
class DownloadEntry:
    browser: str
    profile: str
    url: str
    target_path: str
    total_bytes: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    mime_type: str = ""
    state: str = ""

@dataclass
class BrowserProfile:
    browser_name: str
    profile_name: str
    profile_path: str
    passwords: list[SavedPassword] = field(default_factory=list)
    history: list[HistoryEntry] = field(default_factory=list)
    cookies: list[Cookie] = field(default_factory=list)
    autofill: list[AutofillEntry] = field(default_factory=list)
    bookmarks: list[Bookmark] = field(default_factory=list)
    downloads: list[DownloadEntry] = field(default_factory=list)

@dataclass
class ForensicReport:
    machine_name: str
    os_info: str
    extraction_time: datetime
    examiner: str
    profiles: list[BrowserProfile] = field(default_factory=list)
