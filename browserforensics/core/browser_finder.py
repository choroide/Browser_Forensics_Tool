import platform
import os
import configparser
from pathlib import Path
import logging

from browserforensics.constants import CHROMIUM_BROWSERS, FIREFOX_BROWSERS

logger = logging.getLogger('browserforensics')

def _resolve_path(path_template: str | None) -> Path | None:
    if path_template is None:
        return None
    expanded = os.path.expandvars(path_template)
    return Path(expanded).expanduser()

def _find_chromium_profiles(user_data_path: Path) -> list[str]:
    profiles = []
    if not user_data_path.exists() or not user_data_path.is_dir():
        return profiles
    
    # Opera check: root is profile
    if (user_data_path / 'History').exists():
        profiles.append('')
        return profiles
        
    for item in user_data_path.iterdir():
        if item.is_dir() and (item.name == 'Default' or item.name.startswith('Profile ')):
            for file_name in ('History', 'Login Data', 'Cookies', 'Bookmarks'):
                if (item / file_name).exists():
                    profiles.append(item.name)
                    break
    return profiles

def _find_firefox_profiles(firefox_path: Path) -> list[dict]:
    profiles = []
    if not firefox_path.exists():
        return profiles
        
    profiles_ini = firefox_path / 'profiles.ini'
    if profiles_ini.exists():
        config = configparser.ConfigParser()
        config.read(profiles_ini)
        
        for section in config.sections():
            if section.startswith('Profile'):
                name = config.get(section, 'Name', fallback=None)
                path_str = config.get(section, 'Path', fallback=None)
                is_relative = config.getint(section, 'IsRelative', fallback=1)
                
                if name and path_str:
                    if is_relative:
                        profile_path = firefox_path / path_str
                    else:
                        profile_path = Path(path_str)
                    
                    if profile_path.exists():
                        profiles.append({'name': name, 'path': profile_path})
    else:
        # Fallback
        for item in firefox_path.iterdir():
            if item.is_dir() and '.default' in item.name:
                profiles.append({'name': item.name, 'path': item})
                
    return profiles

def find_installed_browsers() -> list[dict]:
    installed = []
    current_os = platform.system()
    
    for browser_name, paths in CHROMIUM_BROWSERS.items():
        path_template = paths.get(current_os)
        path = _resolve_path(path_template)
        
        if path and path.exists():
            profiles = _find_chromium_profiles(path)
            if profiles:
                installed.append({
                    "name": browser_name,
                    "engine": "chromium",
                    "user_data_path": path,
                    "profiles": profiles
                })
                logger.info(f"Found {browser_name} with {len(profiles)} profiles at {path}")
                for p in profiles:
                    logger.debug(f"  Profile: {p or 'Root'}")
            else:
                logger.debug(f"Found {browser_name} dir at {path} but no profiles")
        else:
            logger.debug(f"Skipped {browser_name} (path {path} not found)")
            
    for browser_name, paths in FIREFOX_BROWSERS.items():
        path_template = paths.get(current_os)
        path = _resolve_path(path_template)
        
        if path and path.exists():
            profiles = _find_firefox_profiles(path)
            if profiles:
                installed.append({
                    "name": browser_name,
                    "engine": "firefox",
                    "user_data_path": path,
                    "profiles": profiles
                })
                logger.info(f"Found {browser_name} with {len(profiles)} profiles at {path}")
                for p in profiles:
                    logger.debug(f"  Profile: {p['name']} at {p['path']}")
            else:
                logger.debug(f"Found {browser_name} dir at {path} but no profiles")
        else:
            logger.debug(f"Skipped {browser_name} (path {path} not found)")
            
    return installed
