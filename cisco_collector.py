
#!/usr/bin/env python3
"""Collect Cisco PSIRT advisories and enrich affected/fixed releases from Cisco CSAF."""
import json
import os
import re
import time
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
        date = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)
    except ValueError:
        return None


def rfc822(value):
    return format_datetime(parse_date(value) or datetime.now(timezone.utc))


def product_id_names(csaf):
    """Map CSAF product IDs to full family + version names, without using status assumptions."""
    names = {}

    def walk(node, family=''):
        category = node.get('category', '')
        label = str(node.get('name') or '').strip()
        if category in ('product_family', 'product_name') and label:
            family = label
        product = node.get('product') or {}
        pid = product.get('product_id')
        if pid:
            version = str(product.get('name') or label).strip()
            names[pid] = (family + ' ' + version).strip() if family and version != family else (version or family)
        for child in node.get('branches') or []:
            walk(child, family)

    for branch in (csaf.get('product_tree') or {}).get('branches') or []:
        walk(branch)
    for rel in (csaf.get('product_tree') or {}).get('relationships') or []:
        full = rel.get('full_product_name') or {}
        if full.get('product_id') and full.get('name'):
            names[full['product_id']] = full['name']
    return names


def extract_ise_fixed_notes(csaf):
    """Strictly parse the explicitly documented Cisco ISE fixed-release table.

    Other vendors/products or different table formats are deliberately not guessed.
    """
    title = str((csaf.get('document') or {}).get('title') or '')
    if 'Identity Services Engine' not in title:
        return []
    for note in (csaf.get('document') or {}).get('notes') or []:
        if note.get('title') != 'Fixed Software':
            continue
        content = re.sub(r'<[^>]*>', '', str(note.get('text') or ''))
        if 'Cisco ISE and ISE-PIC Release' not in content or 'First Fixed Release' not in content:
            continue
        results = []
        for release in ('3.3', '3.4', '3.5'):
            match = re.search(r'(?<![\d.])' + re.escape(release) + r'(?:\(\d+\))?\s+(3\.\d+\s+Patch\s+\d+)', content)
            if match:
                results.append('Cisco ISE ' + match.group(1))
        return results
    return []


def enrich_from_csaf(csaf):
    names = product_id_names(csaf)
    affected = set()
    fixed = set()
    unresolved = set()
    for vulnerability in csaf.get('vulnerabilities') or []:
        status = vulnerability.get('product_status') or {}
        for pid in status.get('known_affected') or []:
            if pid in names:
                affected.add(names[pid])
            else:
                unresolved.add(pid)
        for key in ('fixed', 'first_fixed'):
            for pid in status.get(key) or []:
                if pid in names:
                    fixed.add(names[pid])
                else:
                    unresolved.add(pid)
    # The vendor_fix remediation product_ids refer to affected products,
    # NOT to fixed releases. Never use them for FixedVersion.
    if not fixed:
        fixed.update(extract_ise_fixed_notes(csaf))
    return sorted(affected), sorted(fixed), sorted(unresolved)


def fetch_csaf(session, url):
    if not url or not url.startswith('https://sec.cloudapps.cisco.com/'):
        return None
    for attempt in range(3):
        try:
            response = session.get(url, headers={'Accept': 'application/json'}, timeout=35)
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            if attempt == 2:
                print(f'WARNING: CSAF unavailable: {url}: {exc}')
            else:
                time.sleep(2 ** attempt)
    return None


def main():
    client_id = os.environ['CISCO_CLIENT_ID']
    client_secret = os.environ['CISCO_CLIENT_SECRET']
    session = requests.Session()
    token_resp = session.post(TOKEN_URL, data={
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
    }, timeout=30)
    token_resp.raise_for_status()
    token = token_resp.json()['access_token']
    headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
    advisories = []
    for page in range(1, 3):
        response = session.get(API_URL, headers=headers, params={
            'pageIndex': page, 'pageSize': 50, 'productNames': 'true',
        }, timeout=45)
        response.raise_for_status()
        batch = response.json().get('advisories', [])
        if not isinstance(batch, list):
            raise ValueError('Unexpected API response: advisories is not a list')
        advisories.extend(batch)
        if len(batch) < 50:
            break
    unique = {a['advisoryId']: a for a in advisories if isinstance(a, dict) and a.get('advisoryId')}
    items = sorted(unique.values(), key=lambda a: a.get('lastUpdated') or a.get('firstPublished') or '', reverse=True)
    output = []
    rss = ET.Element('rss', version='2.0')
    channel = ET.SubElement(rss, 'channel')
    for tag, value in [
        ('title', 'Cisco PSIRT Enriched Advisories'),
        ('link', 'https://sec.cloudapps.cisco.com/security/center/publicationListing.x'),
        ('description', 'Cisco PSIRT advisories enriched from Cisco openVuln API'),
    ]:
        ET.SubElement(channel, tag).text = value
    for a in items:
        severity = str(a.get('sir') or 'Unknown').upper()
        cves = a.get('cves') or []
        products = a.get('productNames') or []
        if not isinstance(cves, list):
            cves = [str(cves)]
        if not isinstance(products, list):
            products = [str(products)]
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
        csaf = fetch_csaf(session, record['CSAFURL'])
        if csaf:
            affected, fixed, unresolved = enrich_from_csaf(csaf)
            record['AffectedVersions'] = affected
            record['FixedVersion'] = fixed
            if unresolved:
                print(f"WARNING: {record['AdvisoryKey']}: {len(unresolved)} CSAF product IDs unresolved")
        output.append(record)
        entry = ET.SubElement(channel, 'item')
        for tag, val in [
            ('title', record['Title']),
            ('link', record['URL']),
            ('guid', record['URL'] or record['AdvisoryKey']),
            ('description', json.dumps(record, ensure_ascii=False, separators=(',', ':'))),
            ('pubDate', rfc822(record['LastUpdated'] or record['OriginalPublishedDate'])),
        ]:
            ET.SubElement(entry, tag).text = val
    (BASE / 'cisco_advisories.json').write_text(json.dumps(output, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    ET.indent(rss, space='  ')
    ET.ElementTree(rss).write(BASE / 'cisco_enriched.xml', encoding='utf-8', xml_declaration=True)
    print(f'Collected {len(output)} Cisco advisories; wrote JSON and RSS')
    print('Severity counts:', {s: sum(x['Severity'] == s for x in output) for s in sorted(set(x['Severity'] for x in output))})


if __name__ == '__main__':
    main()
