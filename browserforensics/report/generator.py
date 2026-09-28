"""HTML report generator using Jinja2."""
import json
import logging
from pathlib import Path
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup

from browserforensics.models.data_models import ForensicReport
from browserforensics.report.charts import prepare_chart_data
from browserforensics.utils.time_utils import datetime_to_str

logger = logging.getLogger('browserforensics')


def _tojson_safe(x: object) -> Markup:
    """Serialize to JSON and return as Markup to prevent Jinja2 autoescaping.

    Without Markup wrapping, Jinja2's autoescape converts quotes to &quot;
    inside <script> tags, which breaks JavaScript parsing entirely.
    """
    return Markup(json.dumps(x, default=str))


def generate_html_report(report: ForensicReport, output_path: str) -> None:
    """Generate a self-contained HTML forensic report."""
    template_dir = Path(__file__).parent / 'templates'
    
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html']),
    )
    
    # Register custom filters
    env.filters['datetime_str'] = datetime_to_str
    env.filters['tojson_safe'] = _tojson_safe
    
    template = env.get_template('report.html')
    chart_data = prepare_chart_data(report)
    
    # Calculate summary stats
    total_passwords = sum(len(p.passwords) for p in report.profiles)
    total_history = sum(len(p.history) for p in report.profiles)
    total_cookies = sum(len(p.cookies) for p in report.profiles)
    total_autofill = sum(len(p.autofill) for p in report.profiles)
    total_bookmarks = sum(len(p.bookmarks) for p in report.profiles)
    total_downloads = sum(len(p.downloads) for p in report.profiles)
    
    html = template.render(
        report=report,
        charts=chart_data,
        total_passwords=total_passwords,
        total_history=total_history,
        total_cookies=total_cookies,
        total_autofill=total_autofill,
        total_bookmarks=total_bookmarks,
        total_downloads=total_downloads,
        generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    )
    
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding='utf-8')
    
    logger.info(f"Report written to: {output.resolve()}")
