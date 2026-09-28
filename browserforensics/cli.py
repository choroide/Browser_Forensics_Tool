"""Command-line interface for BrowserForensics."""

import argparse
import logging
import os
import platform
import sys
from datetime import datetime
from pathlib import Path

from browserforensics import __version__
from browserforensics.core.browser_finder import find_installed_browsers
from browserforensics.browsers.chromium import ChromiumExtractor
from browserforensics.browsers.firefox import FirefoxExtractor
from browserforensics.models.data_models import ForensicReport, BrowserProfile
from browserforensics.report.generator import generate_html_report
from browserforensics.utils.logger import setup_logger

logger = logging.getLogger("browserforensics")

DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER  ⚠️                         ║
║                                                                      ║
║  BrowserForensics is intended for AUTHORIZED forensic investigations ║
║  and security assessments ONLY. Unauthorized access to computer      ║
║  systems or private data is ILLEGAL and UNETHICAL.                   ║
║                                                                      ║
║  By proceeding, you confirm that you have proper authorization to    ║
║  examine the browser data on this system.                            ║
╚══════════════════════════════════════════════════════════════════════╝
"""

BANNER = r"""
  ____                                  _____                         _
 |  _ \                                |  ___|                       (_)
 | |_) |_ __ _____      _____  ___ _ __| |_ ___  _ __ ___ _ __  ___ _  ___ ___
 |  _ <| '__/ _ \ \ /\ / / __|/ _ \ '__|  _/ _ \| '__/ _ \ '_ \/ __| |/ __/ __|
 | |_) | | | (_) \ V  V /\__ \  __/ |  | || (_) | | |  __/ | | \__ \ | (__\__ \
 |____/|_|  \___/ \_/\_/ |___/\___|_|  \_| \___/|_|  \___|_| |_|___/_|\___|___/
"""


def _print_banner() -> None:
    """Print the ASCII art banner with version info."""
    print(BANNER)
    print(f"                         v{__version__}")
    print("                         Browser Forensics Tool\n")


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="browser-forensics",
        description="BrowserForensics: Extract and analyze forensic artifacts from web browsers.",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-o",
        "--output",
        required=True,
        type=Path,
        help="Output path for the HTML report",
    )
    parser.add_argument(
        "-b",
        "--browsers",
        nargs="*",
        help="Filter specific browsers (chrome, edge, brave, opera, vivaldi, chromium, firefox)",
    )
    parser.add_argument(
        "--profiles",
        nargs="*",
        help="Filter specific profile names",
    )
    parser.add_argument(
        "--no-passwords",
        action="store_true",
        help="Skip password extraction",
    )
    parser.add_argument(
        "--master-password",
        type=str,
        default="",
        help="Firefox master password (if set)",
    )
    parser.add_argument(
        "--examiner",
        type=str,
        help="Examiner name for the report (default: current OS username)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"BrowserForensics {__version__}",
    )

    return parser


def main() -> None:
    """Main CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()

    setup_logger(verbose=args.verbose)

    try:
        _print_banner()
        print(DISCLAIMER)

        # ── Step 1: Discover installed browsers ──
        logger.info("Starting browser discovery...")
        browsers = find_installed_browsers()

        if not browsers:
            logger.error("No supported browsers found on this system.")
            sys.exit(1)

        print("Found Browsers:")
        for b in browsers:
            profile_count = len(b["profiles"])
            print(
                f"  • {b['name']}  (engine: {b['engine']})  "
                f"— {profile_count} profile(s)"
            )
        print()

        # ── Step 2: Apply browser filter ──
        if args.browsers:
            allowed = [x.lower() for x in args.browsers]
            browsers = [
                b
                for b in browsers
                if any(a in b["name"].lower() for a in allowed)
            ]
            if not browsers:
                logger.error("No browsers match the specified filter.")
                sys.exit(1)

        # ── Step 3: Extract data from each browser/profile ──
        extracted_profiles: list[BrowserProfile] = []

        for browser in browsers:
            engine = browser["engine"]
            name = browser["name"]
            user_data_path: Path = browser["user_data_path"]

            for profile_info in browser["profiles"]:

                # Chromium profiles are plain strings (directory names)
                # Firefox profiles are dicts with 'name' and 'path'
                if engine == "chromium":
                    profile_name: str = profile_info  # type: ignore[assignment]

                    # Apply profile filter
                    if args.profiles and not any(
                        p.lower() in profile_name.lower()
                        for p in args.profiles
                    ):
                        continue

                    # Opera stores data directly in user_data_path
                    if profile_name == "":
                        profile_path = user_data_path
                        display_name = "Default"
                    else:
                        profile_path = user_data_path / profile_name
                        display_name = profile_name

                    logger.info(f"Extracting: {name} / {display_name}")

                    try:
                        extractor = ChromiumExtractor(
                            browser_name=name,
                            profile_name=display_name,
                            profile_path=profile_path,
                            user_data_path=user_data_path,
                        )
                        profile_data = extractor.extract_all(
                            skip_passwords=args.no_passwords
                        )
                        extracted_profiles.append(profile_data)
                    except Exception as e:
                        logger.error(
                            f"Failed to extract {name}/{display_name}: {e}"
                        )

                elif engine == "firefox":
                    ff_name: str = profile_info["name"]  # type: ignore[index]
                    ff_path: Path = profile_info["path"]  # type: ignore[index]

                    # Apply profile filter
                    if args.profiles and not any(
                        p.lower() in ff_name.lower() for p in args.profiles
                    ):
                        continue

                    logger.info(f"Extracting: {name} / {ff_name}")

                    try:
                        extractor = FirefoxExtractor(
                            browser_name=name,
                            profile_name=ff_name,
                            profile_path=ff_path,
                            master_password=args.master_password,
                        )
                        profile_data = extractor.extract_all(
                            skip_passwords=args.no_passwords
                        )
                        extracted_profiles.append(profile_data)
                    except Exception as e:
                        logger.error(
                            f"Failed to extract {name}/{ff_name}: {e}"
                        )

                else:
                    logger.warning(f"Unsupported engine: {engine}")

        if not extracted_profiles:
            logger.error("No profile data was successfully extracted.")
            sys.exit(1)

        # ── Step 4: Build the forensic report ──
        try:
            current_user = os.getlogin()
        except Exception:
            current_user = "Unknown"

        report = ForensicReport(
            machine_name=platform.node(),
            os_info=f"{platform.system()} {platform.release()} ({platform.version()})",
            extraction_time=datetime.now(),
            examiner=args.examiner or current_user,
            profiles=extracted_profiles,
        )

        # ── Step 5: Generate the HTML report ──
        logger.info(f"Generating HTML report...")
        generate_html_report(report, str(args.output))

        print(f"\n✅ Extraction complete! Report saved to: {args.output.resolve()}")

        # ── Summary ──
        total_passwords = sum(len(p.passwords) for p in extracted_profiles)
        total_history = sum(len(p.history) for p in extracted_profiles)
        total_cookies = sum(len(p.cookies) for p in extracted_profiles)
        total_autofill = sum(len(p.autofill) for p in extracted_profiles)
        total_bookmarks = sum(len(p.bookmarks) for p in extracted_profiles)
        total_downloads = sum(len(p.downloads) for p in extracted_profiles)

        print("\n📊 Summary:")
        print(f"  Profiles extracted : {len(extracted_profiles)}")
        print(f"  Passwords          : {total_passwords}")
        print(f"  History records    : {total_history}")
        print(f"  Cookies            : {total_cookies}")
        print(f"  Autofill entries   : {total_autofill}")
        print(f"  Bookmarks          : {total_bookmarks}")
        print(f"  Downloads          : {total_downloads}")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
