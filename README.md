<div align="center">

# 🕵️ BrowserForensics

**A powerful cross-platform CLI tool for extracting, analyzing, and visualizing forensic artifacts from web browsers.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)]()

<img src="https://img.shields.io/badge/Chrome-supported-4285F4?style=flat-square&logo=googlechrome&logoColor=white" alt="Chrome"> <img src="https://img.shields.io/badge/Edge-supported-0078D7?style=flat-square&logo=microsoftedge&logoColor=white" alt="Edge"> <img src="https://img.shields.io/badge/Firefox-supported-FF7139?style=flat-square&logo=firefoxbrowser&logoColor=white" alt="Firefox"> <img src="https://img.shields.io/badge/Brave-supported-FB542B?style=flat-square&logo=brave&logoColor=white" alt="Brave"> <img src="https://img.shields.io/badge/Opera-supported-FF1B2D?style=flat-square&logo=opera&logoColor=white" alt="Opera"> <img src="https://img.shields.io/badge/Vivaldi-supported-EF3939?style=flat-square&logo=vivaldi&logoColor=white" alt="Vivaldi">

</div>

---

## 📋 Table of Contents

- [Features](#-features)
- [Supported Browsers](#-supported-browsers)
- [Installation](#-installation)
- [Usage](#-usage)
- [HTML Report](#-html-report)
- [Data Extraction Matrix](#-data-extraction-matrix)
- [Architecture](#-architecture)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [License](#-license)

---

## ✨ Features

### 🔍 Extraction
- **Automatic browser & profile detection** — scans the system for all installed browsers and enumerates every user profile
- **6 forensic data categories** — passwords, browsing history, cookies, autofill data, bookmarks, and downloads
- **Cross-platform decryption** — decrypts Chromium passwords via DPAPI (Windows), Keychain (macOS), and PBKDF2 (Linux); decrypts Firefox passwords via NSS (3DES/AES-256)
- **Safe database access** — copies locked SQLite databases to temp before reading, preserving WAL/SHM journal files for consistency

### 📊 Interactive HTML Report
- **8 Chart.js visualizations** — summary bar chart, activity timeline, top domains, hourly activity heatmap, cookie distribution, download types, password security doughnut, and autofill field analysis
- **Sidebar navigation** — fixed sidebar with section links and live artifact count badges
- **Global search** — single search bar filters across all sections simultaneously (`Ctrl+K` shortcut)
- **Per-column filters** — each table column has its own filter input for precise filtering
- **Apply / Clear filters** — dedicated buttons to apply or reset all filters at once
- **Date range picker** — filter history records by time period with From/To date inputs
- **Sortable columns** — click any column header to sort ascending/descending
- **Pagination** — configurable page sizes (25, 50, 100, All) with full page navigation
- **CSV export** — one-click export of filtered data to CSV for each section
- **Browser filter pills** — filter the entire report by browser with one click
- **Detail modal** — click any row to view full details in a popup with copy-to-clipboard
- **Fullscreen charts** — expand any chart to a fullscreen modal
- **Dark/Light theme** — toggle between dark and light themes
- **Password reveal** — per-password and bulk show/hide toggle
- **Keyboard shortcuts** — `Ctrl+K` for search, `Esc` to close modals
- **Print-optimized** — dedicated print CSS that hides interactive elements
- **Responsive design** — works on desktop and mobile screens

---

## 🌐 Supported Browsers

| Browser | Engine | Windows | Linux | macOS |
|---------|--------|:-------:|:-----:|:-----:|
| **Google Chrome** | Chromium | ✅ | ✅ | ✅ |
| **Microsoft Edge** | Chromium | ✅ | ✅ | ✅ |
| **Brave** | Chromium | ✅ | ✅ | ✅ |
| **Opera** | Chromium | ✅ | ✅ | ✅ |
| **Vivaldi** | Chromium | ✅ | ✅ | ✅ |
| **Chromium** | Chromium | ✅ | ✅ | ✅ |
| **Mozilla Firefox** | Gecko | ✅ | ✅ | ✅ |

---

## 🚀 Installation

### Prerequisites
- Python 3.10 or higher
- pip

### Steps

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/browser-forensics.git
cd browser-forensics

# Install the package
pip install -e .

# Windows only — required for Chromium password decryption
pip install pywin32
```

### Quick Install (without cloning)

```bash
pip install -r requirements.txt
```

---

## 💻 Usage

### Basic Usage

```bash
# Extract from all detected browsers, generate report
browser-forensics -o report.html

# Verbose output for debugging
browser-forensics -o report.html -v
```

### Filtering

```bash
# Extract only from Chrome and Firefox
browser-forensics -o report.html -b chrome firefox

# Extract only specific profiles
browser-forensics -o report.html --profiles Default "Profile 1"

# Skip password extraction (for safety)
browser-forensics -o report.html --no-passwords
```

### Firefox Master Password

```bash
# If Firefox has a master password set
browser-forensics -o report.html --master-password "your_password"
```

### Examiner Info

```bash
# Set examiner name in the report header
browser-forensics -o report.html --examiner "John Doe"
```

### Full Options

```
usage: browser-forensics [-h] -o OUTPUT [-b [BROWSERS ...]] [--profiles [PROFILES ...]]
                         [--no-passwords] [--master-password MASTER_PASSWORD]
                         [--examiner EXAMINER] [-v] [--version]

options:
  -o, --output            Output path for the HTML report (required)
  -b, --browsers          Filter specific browsers (chrome, edge, brave, opera, vivaldi, chromium, firefox)
  --profiles              Filter specific profile names
  --no-passwords          Skip password extraction
  --master-password       Firefox master password (if set)
  --examiner              Examiner name for the report header
  -v, --verbose           Enable verbose/debug logging
  --version               Show version and exit
```

> **Note:** If `browser-forensics` is not on your PATH, use `python -m browserforensics.cli` instead.

---

## 📊 HTML Report

The tool generates a **self-contained HTML report** with no external dependencies (Chart.js is loaded via CDN for visualizations, but all data and tables render without it).

### Report Sections

| Section | Description | Visualizations |
|---------|-------------|----------------|
| 📊 **Executive Summary** | Total counts, detected browsers, profile overview | Artifacts per browser (bar chart) |
| 🔑 **Saved Passwords** | URLs, usernames, decrypted passwords, timestamps | Password security analysis (doughnut) |
| 🌐 **Browsing History** | URLs, titles, visit counts, timestamps | Timeline, top domains, hourly activity |
| 🍪 **Cookies** | Host, name, value, path, expiry, security flags | Cookie domain distribution (doughnut) |
| 📝 **Autofill Data** | Form field names, saved values, usage counts | Most common fields (bar chart) |
| ⭐ **Bookmarks** | Titles, URLs, folder structure, dates | — |
| ⬇️ **Downloads** | URLs, file paths, sizes, MIME types, states | File type distribution (pie chart) |

### Interactive Features

Every table in the report supports:
- 🔍 **Search** — real-time text filtering
- 🔤 **Column filters** — per-column filter inputs below headers
- ↕️ **Sorting** — click column headers to sort asc/desc
- 📄 **Pagination** — 25 / 50 / 100 / All rows per page
- 📥 **CSV Export** — download filtered data as CSV
- 🔎 **Detail View** — click any row for a detail popup with copy support

---

## 🧩 Data Extraction Matrix

| Data Type | Chromium-based | Firefox | Source |
|-----------|:--------------:|:-------:|--------|
| **Passwords** | ✅ | ✅ | `Login Data` SQLite / `logins.json` + `key4.db` |
| **History** | ✅ | ✅ | `History` SQLite / `places.sqlite` |
| **Cookies** | ✅ | ✅ | `Cookies` SQLite / `cookies.sqlite` |
| **Autofill** | ✅ | ✅ | `Web Data` SQLite / `formhistory.sqlite` |
| **Bookmarks** | ✅ | ✅ | `Bookmarks` JSON / `places.sqlite` |
| **Downloads** | ✅ | ✅ | `History` SQLite / `places.sqlite` (annotations) |

### Password Decryption

| Platform | Chromium | Firefox |
|----------|----------|---------|
| **Windows** | DPAPI + AES-256-GCM | 3DES-CBC (legacy) / PBKDF2 + AES-256-CBC (modern) |
| **Linux** | PBKDF2 (`peanuts`) + AES-128-CBC | Same as Windows |
| **macOS** | Keychain + PBKDF2 + AES-128-CBC | Same as Windows |

---

## 🏗️ Architecture

```
browserforensics/
├── __init__.py
├── cli.py                      # CLI entry point & argument parsing
├── constants.py                # Browser path registry
├── browsers/
│   ├── chromium.py             # Chromium extractor (all 6 browsers)
│   └── firefox.py              # Firefox extractor
├── core/
│   ├── browser_finder.py       # Auto-detection of installed browsers
│   ├── db_handler.py           # Safe SQLite reader (copies locked DBs)
│   └── extractor_base.py       # Abstract base class for extractors
├── decryptors/
│   ├── chromium_windows.py     # DPAPI decryption
│   ├── chromium_linux.py       # PBKDF2 decryption
│   ├── chromium_macos.py       # Keychain decryption
│   └── firefox_decrypt.py      # NSS (3DES / AES-256) decryption
├── models/
│   └── data_models.py          # Dataclass models for all artifacts
├── report/
│   ├── charts.py               # Chart.js dataset preparation
│   ├── generator.py            # Jinja2 HTML report generator
│   └── templates/
│       └── report.html         # Self-contained HTML report template
└── utils/
    ├── logger.py               # Colored console logger
    └── time_utils.py           # Timestamp conversion utilities
```

---

## ⚠️ Legal Disclaimer

> **BrowserForensics is intended for AUTHORIZED forensic investigations and security assessments ONLY.**
>
> Unauthorized access to computer systems or private data is **illegal** and **unethical**. By using this tool, you confirm that you have proper legal authorization to examine the browser data on the target system.
>
> The developers assume **no liability** for any misuse of this tool. Users are solely responsible for ensuring compliance with all applicable local, state, national, and international laws and regulations.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ for the digital forensics community**

</div>
