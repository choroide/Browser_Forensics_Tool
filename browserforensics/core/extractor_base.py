from abc import ABC, abstractmethod
from pathlib import Path
import logging
from browserforensics.models.data_models import (
    BrowserProfile, SavedPassword, HistoryEntry, Cookie,
    AutofillEntry, Bookmark, DownloadEntry
)

logger = logging.getLogger('browserforensics')

class BrowserExtractor(ABC):
    """Abstract base class for browser-specific data extractors."""
    
    def __init__(self, browser_name: str, profile_name: str, profile_path: Path):
        self.browser_name = browser_name
        self.profile_name = profile_name
        self.profile_path = profile_path
    
    @abstractmethod
    def extract_passwords(self) -> list[SavedPassword]:
        pass
    
    @abstractmethod
    def extract_history(self) -> list[HistoryEntry]:
        pass
    
    @abstractmethod
    def extract_cookies(self) -> list[Cookie]:
        pass
    
    @abstractmethod
    def extract_autofill(self) -> list[AutofillEntry]:
        pass
    
    @abstractmethod
    def extract_bookmarks(self) -> list[Bookmark]:
        pass
    
    @abstractmethod
    def extract_downloads(self) -> list[DownloadEntry]:
        pass
    
    def extract_all(self, skip_passwords: bool = False) -> BrowserProfile:
        """Run all extractors and return aggregated BrowserProfile."""
        logger.info(f"Extracting data from {self.browser_name} / {self.profile_name}")
        
        profile = BrowserProfile(
            browser_name=self.browser_name,
            profile_name=self.profile_name,
            profile_path=str(self.profile_path),
        )
        
        if not skip_passwords:
            profile.passwords = self._safe_extract("passwords", self.extract_passwords)
        
        profile.history = self._safe_extract("history", self.extract_history)
        profile.cookies = self._safe_extract("cookies", self.extract_cookies)
        profile.autofill = self._safe_extract("autofill", self.extract_autofill)
        profile.bookmarks = self._safe_extract("bookmarks", self.extract_bookmarks)
        profile.downloads = self._safe_extract("downloads", self.extract_downloads)
        
        logger.info(
            f"  → {self.browser_name}/{self.profile_name}: "
            f"{len(profile.passwords)} passwords, "
            f"{len(profile.history)} history, "
            f"{len(profile.cookies)} cookies, "
            f"{len(profile.autofill)} autofill, "
            f"{len(profile.bookmarks)} bookmarks, "
            f"{len(profile.downloads)} downloads"
        )
        
        return profile
    
    def _safe_extract(self, name: str, method) -> list:
        """Call an extraction method, catching and logging any errors."""
        try:
            result = method()
            return result if result else []
        except FileNotFoundError:
            logger.debug(f"  {name}: database file not found (skipped)")
            return []
        except Exception as e:
            logger.warning(f"  {name}: extraction failed — {e}")
            return []
