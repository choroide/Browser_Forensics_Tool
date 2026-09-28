"""Prepare chart datasets for the HTML report."""
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from browserforensics.models.data_models import ForensicReport


def prepare_chart_data(report: ForensicReport) -> Dict[str, Any]:
    """Prepare all chart datasets for the HTML report."""
    return {
        "summary": _artifact_counts_per_browser(report),
        "history_timeline": _history_over_time(report),
        "top_domains": _top_visited_domains(report),
        "cookie_domains": _cookie_domain_distribution(report),
        "download_types": _download_mime_distribution(report),
        "hourly_activity": _hourly_activity_distribution(report),
        "password_stats": _password_statistics(report),
        "autofill_fields": _autofill_field_distribution(report),
    }


def _artifact_counts_per_browser(report: ForensicReport) -> Dict[str, Any]:
    labels = []
    passwords_data = []
    history_data = []
    cookies_data = []
    autofill_data = []
    bookmarks_data = []
    downloads_data = []
    
    for profile in report.profiles:
        browser_name = f"{profile.browser_name} - {profile.profile_name}" if profile.profile_name else profile.browser_name
        labels.append(browser_name)
        passwords_data.append(len(profile.passwords))
        history_data.append(len(profile.history))
        cookies_data.append(len(profile.cookies))
        autofill_data.append(len(profile.autofill))
        bookmarks_data.append(len(profile.bookmarks))
        downloads_data.append(len(profile.downloads))
        
    return {
        "labels": labels,
        "datasets": [
            {"label": "Passwords", "data": passwords_data, "backgroundColor": "#e94560"},
            {"label": "History", "data": history_data, "backgroundColor": "#0f3460"},
            {"label": "Cookies", "data": cookies_data, "backgroundColor": "#533483"},
            {"label": "Autofill", "data": autofill_data, "backgroundColor": "#16213e"},
            {"label": "Bookmarks", "data": bookmarks_data, "backgroundColor": "#1a73e8"},
            {"label": "Downloads", "data": downloads_data, "backgroundColor": "#00b4d8"},
        ]
    }


def _history_over_time(report: ForensicReport) -> Dict[str, Any]:
    counts = Counter()
    ninety_days_ago = datetime.now(tz=timezone.utc) - timedelta(days=90)
    for profile in report.profiles:
        for entry in profile.history:
            if entry.last_visit_time and entry.last_visit_time >= ninety_days_ago:
                date_str = entry.last_visit_time.strftime("%Y-%m-%d")
                counts[date_str] += 1
                
    sorted_dates = sorted(counts.keys())
    return {
        "labels": sorted_dates,
        "data": [counts[d] for d in sorted_dates]
    }


def _top_visited_domains(report: ForensicReport, limit: int = 20) -> Dict[str, Any]:
    counts = Counter()
    for profile in report.profiles:
        for entry in profile.history:
            if not entry.url:
                continue
            try:
                parsed = urlparse(entry.url)
                if parsed.netloc:
                    counts[parsed.netloc] += (entry.visit_count or 1)
            except Exception:
                pass
                
    top = counts.most_common(limit)
    return {
        "labels": [domain for domain, _ in top],
        "data": [count for _, count in top]
    }


def _cookie_domain_distribution(report: ForensicReport, limit: int = 15) -> Dict[str, Any]:
    counts = Counter()
    for profile in report.profiles:
        for cookie in profile.cookies:
            domain = cookie.host.lstrip('.') if cookie.host else 'unknown'
            counts[domain] += 1
            
    top = counts.most_common(limit)
    others = sum(count for _, count in counts.most_common()[limit:])
    
    labels = [domain for domain, _ in top]
    data = [count for _, count in top]
    
    if others > 0:
        labels.append("Others")
        data.append(others)
        
    return {
        "labels": labels,
        "data": data
    }


def _download_mime_distribution(report: ForensicReport) -> Dict[str, Any]:
    counts = Counter()
    total = 0
    for profile in report.profiles:
        for download in profile.downloads:
            total += 1
            if download.mime_type:
                counts[download.mime_type] += 1
            elif download.target_path:
                ext = download.target_path.split('.')[-1].lower() if '.' in download.target_path else 'unknown'
                counts[ext] += 1
            else:
                counts['unknown'] += 1
                
    labels = []
    data = []
    other_count = 0
    
    for mime, count in counts.items():
        if total > 0 and (count / total) < 0.02:
            other_count += count
        else:
            labels.append(mime)
            data.append(count)
            
    if other_count > 0:
        labels.append("Other")
        data.append(other_count)
        
    return {
        "labels": labels,
        "data": data
    }


def _hourly_activity_distribution(report: ForensicReport) -> Dict[str, Any]:
    counts = Counter()
    for profile in report.profiles:
        for entry in profile.history:
            if entry.last_visit_time:
                hour = entry.last_visit_time.strftime("%H:00")
                counts[hour] += (entry.visit_count or 1)
                
    labels = [f"{i:02d}:00" for i in range(24)]
    data = [counts[label] for label in labels]
    
    return {
        "labels": labels,
        "data": data
    }


def _password_statistics(report: ForensicReport) -> Dict[str, Any]:
    total = 0
    empty = 0
    password_freq = Counter()
    
    for profile in report.profiles:
        for pw in profile.passwords:
            total += 1
            if not pw.password:
                empty += 1
            else:
                password_freq[pw.password] += 1
                
    unique = len(password_freq)
    reused = sum(1 for pw, count in password_freq.items() if count > 1)
    
    return {
        "total": total,
        "unique": unique,
        "reused": reused,
        "empty": empty,
        "labels": ["Unique", "Reused", "Empty"],
        "data": [unique, reused, empty]
    }


def _autofill_field_distribution(report: ForensicReport, limit: int = 15) -> Dict[str, Any]:
    counts = Counter()
    for profile in report.profiles:
        for autofill in profile.autofill:
            if autofill.field_name:
                counts[autofill.field_name] += 1
                
    top = counts.most_common(limit)
    return {
        "labels": [name for name, _ in top],
        "data": [count for _, count in top]
    }
