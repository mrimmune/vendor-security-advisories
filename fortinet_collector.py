
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
CONTENT_FIELDS = (
    'Title',
    'Severity',
    'CVE',
    'AffectedProduct',
    'AffectedVersions',
    'FixedVersion',
)

session = requests.Session()
session.headers.update({
    'User-Agent': 'VendorSecurityAdvisoryCollector/1.1',
    'Accept': 'text/html,application/xhtml+xml,application/rss+xml',
})


def clean(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def get_advisory(url):
    result = {
        'AffectedProduct': [],
        'AffectedVersions': [],
        'FixedVersion': [],
        'CVE': [],
        'Severity': 'Unknown',
        'ExtractionStatus': 'Unverified',
    }

    parsed = urlparse(url)
    if (
        parsed.scheme != 'https'
        or parsed.hostname != 'fortiguard.fortinet.com'
    ):
        raise ValueError('Unexpected advisory URL')

    response = session.get(url, timeout=25)
    response.raise_for_status()

    if urlparse(response.url).hostname != 'fortiguard.fortinet.com':
        raise ValueError('Unexpected advisory redirect')

    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text(' ', strip=True)

    result['CVE'] = sorted(
        set(re.findall(r'CVE-\d{4}-\d{4,}', text, re.I))
    )

    for severity in ('Critical', 'High', 'Medium', 'Low'):
        if re.search(
            r'\bSeverity\s*:?\s*' + severity + r'\b',
            text,
            re.I,
        ):
            result['Severity'] = severity.upper()
            break

    for table in soup.find_all('table'):
        headers = [
            clean(th.get_text(' ', strip=True)).lower()
            for th in table.find_all('th')
        ]

        if not {'version', 'affected', 'solution'}.issubset(
            set(headers)
        ):
            continue

        for row in table.find_all('tr'):
            cells = row.find_all('td')

            if len(cells) < 3:
                continue

            product, affected, fixed = [
                clean(c.get_text(' ', strip=True))
                for c in cells[:3]
            ]

            if not product or not affected:
                continue

            if affected.casefold() in (
                'not affected',
                'not applicable',
                'n/a',
            ):
                continue

            if product not in result['AffectedProduct']:
                result['AffectedProduct'].append(product)

            result['AffectedVersions'].append({
                'Product': product,
                'Versions': affected,
            })

            result['FixedVersion'].append({
                'Product': product,
                'Solution': fixed,
            })

    result['ExtractionStatus'] = (
        'Version table extracted'
        if result['AffectedVersions']
        else 'Version table not found'
    )

    return result


def content_signature(record):
    payload = {
        key: record.get(
            key,
            [] if key in (
                'CVE',
                'AffectedProduct',
                'AffectedVersions',
                'FixedVersion',
            ) else '',
        )
        for key in CONTENT_FIELDS
    }

    for key in ('CVE', 'AffectedProduct'):
        payload[key] = sorted(payload[key])

    for key in ('AffectedVersions', 'FixedVersion'):
        payload[key] = sorted(
            payload[key],
            key=lambda v: json.dumps(v, sort_keys=True),
        )

    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(',', ':'),
    )

    return hashlib.sha256(
        raw.encode('utf-8')
    ).hexdigest()


def load_previous():
    if not JSON_FILE.exists():
        return {}

    try:
        data = json.loads(
            JSON_FILE.read_text(encoding='utf-8')
        )

        return {
            r['URL']: r
            for r in data
            if isinstance(r, dict) and r.get('URL')
        }

    except (ValueError, OSError, TypeError):
        raise RuntimeError(
            'Existing advisory state is unreadable; '
            'refusing to reset change history'
        )


def rss_date(value):
    if not value:
        return None

    try:
        dt = parsedate_to_datetime(value)

    except (TypeError, ValueError):
        try:
            dt = datetime.fromisoformat(
                value.replace('Z', '+00:00')
            )
        except (TypeError, ValueError):
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return format_datetime(
        dt.astimezone(timezone.utc)
    )


def make_rss(advisories):
    rss = ET.Element('rss', {'version': '2.0'})
    channel = ET.SubElement(rss, 'channel')

    for tag, value in (
        ('title', 'Fortinet PSIRT Enriched Advisories'),
        ('link', 'https://fortiguard.fortinet.com/psirt'),
        (
            'description',
            'Fortinet PSIRT advisories enriched '
            'with affected and fixed versions',
        ),
        ('language', 'en'),
        (
            'lastBuildDate',
            format_datetime(datetime.now(timezone.utc)),
        ),
    ):
        ET.SubElement(channel, tag).text = value

    for record in advisories:
        if (
            record.get('ExtractionStatus')
            != 'Version table extracted'
        ):
            continue

        item = ET.SubElement(channel, 'item')

        ET.SubElement(
            item, 'title'
        ).text = record['Title']

        ET.SubElement(
            item, 'link'
        ).text = record['URL']

        ET.SubElement(
            item,
            'guid',
            {'isPermaLink': 'true'},
        ).text = record['URL']

        published = rss_date(
            record.get('PublishedDate')
        )

        updated = rss_date(
            record.get('ContentUpdatedAt')
        )

        if updated or published:
            ET.SubElement(
                item, 'pubDate'
            ).text = updated or published

        description = {
            'Severity': record['Severity'],
            'CVE': record['CVE'],
            'AffectedProduct': record['AffectedProduct'],
            'AffectedVersions': record['AffectedVersions'],
            'FixedVersion': record['FixedVersion'],
            'ExtractionStatus': record['ExtractionStatus'],
            'OriginalPublishedDate': record.get(
                'PublishedDate', ''
            ),
        }

        ET.SubElement(
            item, 'description'
        ).text = json.dumps(
            description,
            ensure_ascii=False,
            separators=(',', ':'),
        )

    tree = ET.ElementTree(rss)
    ET.indent(tree, space='  ')

    tree.write(
        XML_FILE,
        encoding='utf-8',
        xml_declaration=True,
    )


def main():
    previous = load_previous()

    response = session.get(
        RSS_URL,
        timeout=30,
    )
    response.raise_for_status()

    feed = feedparser.parse(response.content)

    if feed.bozo and not feed.entries:
        raise RuntimeError(
            'Unable to parse Fortinet RSS'
        )

    now = datetime.now(timezone.utc).isoformat()

    advisories = []
    changed = 0

    for entry in feed.entries[:MAX_ITEMS]:
        url = entry.get('link', '')

        if not url:
            continue

        record = {
            'Vendor': 'Fortinet',
            'Title': clean(
                entry.get('title', '')
            ),
            'URL': url,
            'PublishedDate': entry.get(
                'published', ''
            ),
            'CollectedAt': now,
        }

        old = previous.get(url)

        try:
            record.update(
                get_advisory(url)
            )

        except Exception as exc:
            if (
                old
                and old.get('ExtractionStatus')
                == 'Version table extracted'
            ):
                record = dict(old)
                record['CollectedAt'] = now
                record['LastFetchError'] = str(exc)

                advisories.append(record)
                continue

            record['ExtractionStatus'] = 'Failed'
            record['ExtractionError'] = str(exc)

            advisories.append(record)
            continue

        if (
            record['ExtractionStatus']
            == 'Version table extracted'
        ):
            signature = content_signature(record)

            if (
                old
                and old.get('ExtractionStatus')
                == 'Version table extracted'
            ):
                previous_signature = content_signature(old)

                if signature == previous_signature:
                    record['ContentUpdatedAt'] = old.get(
                        'ContentUpdatedAt', ''
                    )
                else:
                    record['ContentUpdatedAt'] = now
                    changed += 1

            else:
                record['ContentUpdatedAt'] = ''

            record['ContentHash'] = signature

        elif (
            old
            and old.get('ExtractionStatus')
            == 'Version table extracted'
        ):
            record = dict(old)
            record['CollectedAt'] = now
            record['LastFetchError'] = (
                'Version table not found in latest fetch'
            )

        advisories.append(record)

    JSON_FILE.write_text(
        json.dumps(
            advisories,
            indent=2,
            ensure_ascii=False,
        ),
        encoding='utf-8',
    )

    make_rss(advisories)

    valid = sum(
        r.get('ExtractionStatus')
        == 'Version table extracted'
        for r in advisories
    )

    print(
        f'Collected {len(advisories)} advisories; '
        f'verified {valid}; changed {changed}'
    )

    print(
        f'Created {JSON_FILE} and {XML_FILE}'
    )


if __name__ == '__main__':
    main()
