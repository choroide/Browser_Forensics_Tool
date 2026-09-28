import shutil
import sqlite3
import tempfile
import logging
from pathlib import Path

logger = logging.getLogger('browserforensics')

class SafeSQLiteReader:
    """Context manager that copies a SQLite DB to temp dir before opening.
    
    This handles the common case where browsers hold locks on their DBs.
    Copies the main DB file plus any WAL/SHM journal files for consistency.
    """
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._tmp_dir: str | None = None
        self._conn: sqlite3.Connection | None = None
    
    def __enter__(self) -> sqlite3.Connection:
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {self.db_path}")
        
        self._tmp_dir = tempfile.mkdtemp(prefix="browserforensics_")
        tmp_db = Path(self._tmp_dir) / self.db_path.name
        
        # Copy main database
        shutil.copy2(self.db_path, tmp_db)
        
        # Copy WAL and SHM files if they exist (for write-ahead logging consistency)
        for suffix in ("-wal", "-shm"):
            journal = self.db_path.parent / (self.db_path.name + suffix)
            if journal.exists():
                shutil.copy2(journal, Path(self._tmp_dir) / journal.name)
        
        self._conn = sqlite3.connect(str(tmp_db))
        self._conn.row_factory = sqlite3.Row
        
        # Set read-only pragmas for safety
        self._conn.execute("PRAGMA query_only = ON")
        
        logger.debug(f"Opened database copy: {self.db_path.name}")
        return self._conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
        if self._tmp_dir:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
        return False  # Don't suppress exceptions
