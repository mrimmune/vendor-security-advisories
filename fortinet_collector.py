import hashlib
import json
import re
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

import feedparser
import requests
from bs4 import BeautifulSoup

RSS_URL = 'https://filestore.fortinet.com/fortiguard/rss/ir.xml'
JSON_FILE = Path('fortinet_advisories.json')
XML_FILE = Path('fortinet_enriched.xml')
MAX_ITEMS = 20
CONTENT_FIELDS = ('Title', 'Severity', 'CVE', 'AffectedProduct', 'AffectedVersions', 'FixedVersion')

session = requests.Session()
session.headers.update({
    'User-Agent': 'VendorSecurityAdvisoryCollector/1.1',
    'Accept': 'text/html,application/xhtml+xml,application/rss+xml',
})


def clean(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def get_advisory(url):
    result = {
        'AffectedProduct': [], 'AffectedVersions': [], 'FixedVersion': [],
        'CVE': [], 'Severity': 'Unknown', 'ExtractionStatus': 'Unverified',
    }
    parsed = urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname != 'fortiguard.fortinet.com':
        raise ValueError('Unexpected advisory URL')
    response = session.get(url, timeout=25)
    response.raise_for_status()
    if urlparse(response.url).hostname != 'fortiguard.fortinet.com':
        raise ValueError('Unexpected advisory redirect')
    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text(' ', strip=True)
    result['CVE'] = sorted(set(re.findall(r'CVE-\d{4}-\d{4,}', text, re.I)))
    for severity in ('Critical', 'High', 'Medium', 'Low'):
        if re.search(r'\bSeverity\s*:?\s*' + severity + r'\b', text, re.I):
            result['Severity'] = severity.upper()
            break
    for table in soup.find_all('table'):
        headers = [clean(th.get_text(' ', strip=True)).lower() for th in table.find_all('th')]
        if not {'version', 'affected', 'solution'}.issubset(set(headers)):
            continue
        for row in table.find_all('tr'):
            cells = row.find_all('td')
            if len(cells) < 3:
                continue
            product, affected, fixed = [clean(c.get_text(' ', strip=True)) for c in cells[:3]]
            if not product or not affected or affected.casefold() in ('not affected', 'not applicable', 'n/a'):
                continue
            if product not in result['AffectedProduct']:
                result['AffectedProduct'].append(product)
            result['AffectedVersions'].append({'Product': product, 'Versions': affected})
            result['FixedVersion'].append({'Product': product, 'Solution': fixed})
    result['ExtractionStatus'] = ('Version table extracted' if result['AffectedVersions']
                                  else 'Version table not found')
    return result


def content_signature(record):
    # Canonicalize list order so a harmless table reordering is not an update.
    payload = {key: record.get(key, [] if key in ('CVE', 'AffectedProduct',
              'AffectedVersions', 'FixedVersion') else '') for key in CONTENT_FIELDS}
    for key in ('CVE', 'AffectedProduct'):
        payload[key] = sorted(payload[key])
    for key in ('AffectedVersions', 'FixedVersion'):
        payload[key] = sorted(payload[key], key=lambda v: json.dumps(v, sort_keys=True))
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def load_previous():
    if not JSON_FILE.exists():
        return {}
    try:
        data = json.loads(JSON_FILE.read_text(encoding='utf-8'))
        return {r['URL']: r for r in data if isinstance(r, dict) and r.get('URL')}
    except (ValueError, OSError, TypeError):
        raise RuntimeError('Existing advisory state is unreadable; refusing to reset change history')


def rss_date(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
