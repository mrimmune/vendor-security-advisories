#!/usr/bin/env python3
"""Cisco PSIRT Collector v4: CSAF and verified fixed-release HTML table enrichment."""
import json
import html
import os
import re
import time
from datetime import datetime, timezone
from email.utils import format_datetime
from html.parser import HTMLParser
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


def versioned_name(name):
    """Recognize dotted Cisco versions and CUCM SU, IOS XE and train formats.

    This is a classification heuristic, not evidence of vulnerability status.
    """
    name = str(name or '')
    patterns = (
        r'(?<![A-Za-z0-9])\d+\.\d+(?:\.\d+)*(?:\([^)]{1,12}\))?(?:[-.]\d+)?',
        r'(?<![A-Za-z0-9])\d{1,2}SU\d+[a-z]?(?![A-Za-z0-9])',
        r'(?<![A-Za-z0-9])\d{1,2}(?![A-Za-z0-9])(?=\s*$)',
    )
    return any(re.search(p, name, re.I) for p in patterns)


class _FixedTableParser(HTMLParser):
    """Read HTML table cells without adding a third-party dependency."""
    def __init__(self):
        super().__init__()
        self.tables = []
        self.table = None
        self.row = None
        self.cell = None
        self.depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == 'table':
            if self.depth == 0:
                self.table = []
            self.depth += 1
        elif self.depth and tag == 'tr':
            self.row = []
        elif self.depth and tag in ('td', 'th') and self.row is not None:
            self.cell = []
        elif self.cell is not None and tag == 'br':
            self.cell.append(' ')

    def handle_data(self, data):
        if self.cell is not None:
            self.cell.append(data)

    def handle_endtag(self, tag):
        if tag in ('td', 'th') and self.cell is not None and self.row is not None:
            self.row.append(' '.join(''.join(self.cell).split()))
            self.cell = None
        elif tag == 'tr' and self.row is not None and self.table is not None:
            if self.row:
                self.table.append(self.row)
            self.row = None
        elif tag == 'table' and self.depth:
            self.depth -= 1
            if self.depth == 0 and self.table is not None:
                self.tables.append(self.table)
                self.table = None


def _explicit_fixed_table_rows(note_text):
    parser = _FixedTableParser()
    parser.feed(note_text)
    for table in parser.tables:
        header_index = None
        fixed_columns = []
        product_columns = []
        for i, row in enumerate(table[:5]):
            lowered = [re.sub(r'\s+', ' ', c).lower() for c in row]
            cols = [j for j, c in enumerate(lowered)
                    if ('fixed' in c and ('release' in c or 'version' in c or 'software' in c))]
            if cols:
                header_index, fixed_columns = i, cols
                product_columns = [j for j, c in enumerate(lowered)
                                   if any(t in c for t in ('product', 'release', 'version', 'software'))
                                   and j not in cols]
                break
        if header_index is None:
            continue
        for row in table[header_index + 1:]:
            if len(row) <= max(fixed_columns):
                continue
            context = ' / '.join(row[j] for j in product_columns if j < len(row))
            for j in fixed_columns:
                yield context, row[j]


def _clean_fixed_cell(cell):
    """Accept explicit release cells, reject placeholders and prose."""
    cell = html.unescape(re.sub(r'<[^>]+>', ' ', str(cell or '')))
    cell = ' '.join(cell.split())
    if not cell or len(cell) > 130 or re.search(
        r'not affected|not vulnerable|no fix|not applicable|under investigation|to be determined|contact tac|see (?:the|below)|\bnone\b|\bn/?a\b',
        cell, re.I):
        return None
    if not versioned_name(cell):
        return None
    # Never interpret an entire explanatory sentence as a release.
    if len(cell.split()) > 12 or re.search(r'[.!?]\s+[A-Z]', cell):
        return None
    return cell


def product_families(csaf):
    """Read actual CSAF product-family nodes, not product-tree release leaves."""
    families = set()

    def walk(branch):
        if branch.get('category') in ('product_family', 'product_name'):
            name = str(branch.get('name') or '').strip()
            if name and not versioned_name(name):
                families.add(name)
        for child in branch.get('branches') or []:
            walk(child)

    for branch in (csaf.get('product_tree') or {}).get('branches') or []:
        walk(branch)
    return sorted(families)


def extract_explicit_fixed_notes(csaf):
    """Extract releases only from explicitly headed Fixed Software table columns.

    Keep context in each value; ambiguous rows are deliberately skipped.
    The special ISE parser is retained for its previously verified format.
    """
    results = set(extract_ise_fixed_notes(csaf))
    for note in (csaf.get('document') or {}).get('notes') or []:
        if str(note.get('title') or '').strip().lower() != 'fixed software':
            continue
        for context, cell in _explicit_fixed_table_rows(str(note.get('text') or '')):
            release = _clean_fixed_cell(cell)
            if not release:
                continue
            # Only a release column plus an identifiable row context is accepted.
            context = ' '.join(context.split())
            if not context or len(context) > 100:
                continue
            if release.lower() in context.lower():
                results.add(context)
            else:
                results.add(f'{context} -> {release}')
    return sorted(results)


def _fixed_table_from_html(page_html):
    """Only trust cells in a table with an explicit First Fixed/Fixed Release header."""
    result = set()
    for context, cell in _explicit_fixed_table_rows(page_html):
        release = _clean_fixed_cell(cell)
        context = ' '.join(context.split())
        if not release or not context or len(context) > 100:
            continue
        # Exclude non-release instructions; do not infer a patch from affected versions.
        if re.search(r'migrate|upgrade|contact|not affected|see|n/a', release, re.I):
            continue
        result.add(f'{context} -> {release}')
    return sorted(result)


def fetch_fixed_from_advisory_html(session, url):
    """Fallback to Cisco's public HTML page; fail closed if the page is inaccessible."""
    if not url.startswith('https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/'):
        return []
    try:
        response = session.get(url, timeout=25, headers={'Accept': 'text/html'})
        response.raise_for_status()
        if len(response.content) > 4_000_000:
            return []
        return _fixed_table_from_html(response.text)
    except requests.RequestException as exc:
        print(f'WARNING: advisory HTML unavailable: {url}: {exc}')
        return []


def extract_fixed_from_csaf_text(csaf):
    """Conservative support for plaintext Cisco fixed-release tables in CSAF notes.

    Cisco serializes some HTML tables into flat text; only explicit 'First Fixed
    Release' followed by 'Patch' values can be reliably recognized without
    row boundaries. Product-specific logic is not inferred from unrelated prose.
    """
    title = str((csaf.get('document') or {}).get('title') or '')
    if 'Identity Services Engine' not in title:
        return []
    results = set()
    for note in (csaf.get('document') or {}).get('notes') or []:
        if str(note.get('title') or '').lower() != 'fixed software':
            continue
        body = html.unescape(str(note.get('text') or ''))
        if 'First Fixed Release' not in body:
            continue
        # Parse only row-like pairs, not free-floating patch numbers.
        for m in re.finditer(r'(?<![\w.])(3\.[1-5])(?:\s*\([^)]{1,40}\))?\s+(3\.[1-5]\s+Patch\s+\d+)\b', body, re.I):
            if m.group(2).split()[0] == m.group(1):
                results.add('Cisco ISE ' + m.group(2))
    return sorted(results)


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
    # Explicit table releases complement CSAF fixed/first_fixed product statuses.
    fixed.update(extract_explicit_fixed_notes(csaf))
    fixed.update(extract_fixed_from_csaf_text(csaf))
    return sorted(x for x in affected if versioned_name(x)), sorted(fixed), sorted(unresolved)


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
            # Only supplement CSAF with first-fixed releases explicitly present
            # in a Cisco advisory HTML table. No inferred release numbers.
            html_fixed = fetch_fixed_from_advisory_html(session, record['URL']) if not fixed else []
            record['FixedVersion'] = sorted(set(fixed) | set(html_fixed))
            families = sorted({p for p in record['AffectedProduct'] if p != 'NA' and not versioned_name(p)})
            # Some API product names are version leaves (e.g. CUCM 14SU1).
            # Preserve them as affected only if CSAF explicitly marks them affected.
            if not families:
                families = product_families(csaf)
            if families:
                record['AffectedProduct'] = families
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
    print('With fixed releases:', sum(bool(x['FixedVersion']) for x in output))
    print('With affected releases:', sum(bool(x['AffectedVersions']) for x in output))
    print('Severity counts:', {s: sum(x['Severity'] == s for x in output) for s in sorted(set(x['Severity'] for x in output))})


if __name__ == '__main__':
    main()
