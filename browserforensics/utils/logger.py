"""Console logger for the application."""

import logging

class ColorFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': '\033[94m',    # Blue
        'INFO': '\033[92m',     # Green
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[91m', # Red
        'RESET': '\033[0m'      # Reset
    }
    PREFIXES = {
        'DEBUG': '[~]',
        'INFO': '[*]',
        'WARNING': '[!]',
        'ERROR': '[✗]',
        'CRITICAL': '[✗]'
    }

    def __init__(self):
        super().__init__('%(prefix)s %(message)s')

    def format(self, record: logging.LogRecord) -> str:
        prefix = self.PREFIXES.get(record.levelname, '[*]')
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Colorize prefix
        record.prefix = f"{color}{prefix}{reset}"
        return super().format(record)

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger('browserforensics')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Avoid duplicate handlers if setup_logger is called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(ColorFormatter())
        logger.addHandler(handler)
        
    return logger
