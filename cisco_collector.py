#!/usr/bin/env python3
"""Collect Cisco PSIRT advisories and publish a Power Automate-friendly RSS feed."""
import json
import os
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from xml.etree import ElementTree as ET

import requests

TOKEN_URL = 'https://id.cisco.com/oauth2/default/v1/token'
API_URL = 'https://apix.cisco.com/security/advisories/v2/all'
BASE = Path(__file__).resolve().parent


def parse_date(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).replace(tzinfo=timezone.utc) if datetime.fromisoformat(value.replace('Z', '+00:00')).tzinfo is None else datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None


def rfc822(value):
    return format_datetime(parse_date(value) or datetime.now(timezone.utc))


def main():
    client_id = os.environ['CISCO_CLIENT_ID']
    client_secret = os.environ['CISCO_CLIENT_SECRET']
    session = requests.Session()
    token_resp = session.post(TOKEN_URL, data={'grant_type': 'client_credentials', 'client_id': client_id, 'client_secret': client_secret}, timeout=30)
    token_resp.raise_for_status()
    token = token_resp.json()['access_token']
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    advisories = []
    for page in range(1, 3):
        response = session.get(API_URL, headers=headers, params={'pageIndex': page, 'pageSize': 50, 'productNames': 'true'}, timeout=45)
        response.raise_for_status()
        batch = response.json().get('advisories', [])
        if not isinstance(batch, list):
            raise ValueError('Unexpected API response: advisories is not a list')
        advisories.extend(batch)
        if len(batch) < 50:
            break
    # Deduplicate and sort by most recent update; do not assume API ordering.
    unique = {a['advisoryId']: a for a in advisories if isinstance(a, dict) and a.get('advisoryId')}
    items = sorted(unique.values(), key=lambda a: a.get('lastUpdated') or a.get('firstPublished') or '', reverse=True)
    output = []
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    for tag, value in [('title', 'Cisco PSIRT Enriched Advisories'), ('link', 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x'), ('description', 'Cisco PSIRT advisories enriched from Cisco openVuln API')]:
        ET.SubElement(channel, tag).text = value
    for a in items:
        severity = str(a.get('sir') or 'Unknown').upper()
        cves = a.get('cves') or []
        products = a.get('productNames') or []
        if not isinstance(cves, list): cves = [str(cves)]
        if not isinstance(products, list): products = [str(products)]
        score = a.get('cvssBaseScore')
        try:
            cvss = float(score) if score not in (None, '', 'NA', 'N/A') else None
        except (TypeError, ValueError):
            cvss = None
        record = {
            'Vendor': 'Cisco',
            'AdvisoryKey': str(a['advisoryId']),
            'Title': str(a.get('advisoryTitle') or a['advisoryId']),
            'URL': str(a.get('publicationUrl') or ''),
            'Severity': severity,
            'CVE': [str(c) for c in cves],
            'CVSS': cvss,
            'AffectedProduct': [str(p).strip() for p in products if str(p).strip()],
            'AffectedVersions': [],
            'FixedVersion': [],
            'OriginalPublishedDate': a.get('firstPublished') or '',
            'LastUpdated': a.get('lastUpdated') or '',
            'Summary': str(a.get('summary') or ''),
            'CSAFURL': str(a.get('csafUrl') or ''),
        }
        output.append(record)
        entry = ET.SubElement(channel, 'item')
        for tag, val in [('title', record['Title']), ('link', record['URL']), ('guid', record['URL'] or record['AdvisoryKey']), ('description', json.dumps(record, ensure_ascii=False, separators=(',', ':'))), ('pubDate', rfc822(record['LastUpdated'] or record['OriginalPublishedDate']))]:
            ET.SubElement(entry, tag).text = val
    (BASE / 'cisco_advisories.json').write_text(json.dumps(output, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    ET.indent(rss, space='  ')
    ET.ElementTree(rss).write(BASE / 'cisco_enriched.xml', encoding='utf-8', xml_declaration=True)
    print(f'Collected {len(output)} Cisco advisories; wrote JSON and RSS')
    print('Severity counts:', {s: sum(x['Severity'] == s for x in output) for s in sorted(set(x['Severity'] for x in output))})


if __name__ == '__main__':
    main()
