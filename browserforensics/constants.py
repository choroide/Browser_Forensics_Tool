"""Constants for the browser forensics tool."""

CHROMIUM_EPOCH_OFFSET = 11644473600

CHROMIUM_BROWSERS = {
    "Google Chrome": {
        "Windows": r"%LOCALAPPDATA%\Google\Chrome\User Data",
        "Linux": "~/.config/google-chrome",
        "Darwin": "~/Library/Application Support/Google/Chrome",
    },
    "Microsoft Edge": {
        "Windows": r"%LOCALAPPDATA%\Microsoft\Edge\User Data",
        "Linux": "~/.config/microsoft-edge",
        "Darwin": "~/Library/Application Support/Microsoft Edge",
    },
    "Brave": {
        "Windows": r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",
        "Linux": "~/.config/BraveSoftware/Brave-Browser",
        "Darwin": "~/Library/Application Support/BraveSoftware/Brave-Browser",
    },
    "Opera": {
        "Windows": r"%APPDATA%\Opera Software\Opera Stable",  # Note: Opera uses %APPDATA% not %LOCALAPPDATA%
        "Linux": "~/.config/opera",
        "Darwin": "~/Library/Application Support/com.operasoftware.Opera",
    },
    "Vivaldi": {
        "Windows": r"%LOCALAPPDATA%\Vivaldi\User Data",
        "Linux": "~/.config/vivaldi",
        "Darwin": "~/Library/Application Support/Vivaldi",
    },
    "Chromium": {
        "Windows": r"%LOCALAPPDATA%\Chromium\User Data",
        "Linux": "~/.config/chromium",
        "Darwin": "~/Library/Application Support/Chromium",
    }
}

FIREFOX_BROWSERS = {
    "Firefox": {
        "Windows": r"%APPDATA%\Mozilla\Firefox",
        "Linux": "~/.mozilla/firefox",
        "Darwin": "~/Library/Application Support/Firefox",
    }
}
