#!/usr/bin/env python3
"""Cisco PSIRT Collector v6.1: CSAF and verified fixed-release HTML table enrichment."""
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


def _is_planned_release(value, as_of=None):
    """Conservatively exclude explicit future/TBD release schedules from available fixes."""
    value = html.unescape(str(value or ''))
    if re.search(r'\b(?:TBD|TBA|planned|scheduled|not yet available|future release|targeted|upcoming)\b', value, re.I):
        return True
    as_of = as_of or datetime.now(timezone.utc)
    months = {name.lower(): i for i, name in enumerate(
        ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'), 1)}
    for m in re.finditer(r'\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+(20\d{2})\b', value, re.I):
        year, month = int(m.group(2)), months[m.group(1)[:3].lower()]
        if (year, month) > (as_of.year, as_of.month):
            return True
    return False


def _clean_fixed_cell(cell):
    """Validate a release cell, never accepting prose or a release-note hyperlink title."""
    cell = html.unescape(re.sub(r'<[^>]+>', ' ', str(cell or '')))
    cell = ' '.join(cell.split())
    if not cell or len(cell) > 130 or re.search(
        r'not affected|not vulnerable|no fix|not applicable|under investigation|to be determined|contact tac|'
        r'see (?:the|below)|\bnone\b|\bn/?a\b|release notes|updated information|revision history|'
        r'\b(?:TBD|TBA|planned|scheduled)\b', cell, re.I):
        return None
    if _is_planned_release(cell) or not versioned_name(cell):
        return None
    if len(cell.split()) > 12 or re.search(r'[.!?]\s+[A-Z]', cell):
        return None
    return cell


def _clean_context(context):
    context = ' '.join(html.unescape(str(context or '')).split())
    if not context or len(context) > 100:
        return None
    if re.search(r'updated information|revision history|release notes|\b(?:TBD|TBA)\b', context, re.I):
        return None
    # Cisco revision-history rows can have numeric revisions like 1.2;
    # require context to identify a software train, product, or affected range.
    if re.fullmatch(r'\d+\.\d+', context) and re.search(r'^1\.[0-9]$', context):
        return None
    return context

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
            context = _clean_context(context)
            if not context:
                continue
            if _is_planned_release(context + ' ' + release):
                continue
            if release.lower() in context.lower():
                results.add(context)
            else:
                results.add(f'{context} -> {release}')
    return sorted(x for x in results if not _is_planned_release(x))


def _fixed_table_from_html(page_html):
    """Only trust cells in a table with an explicit First Fixed/Fixed Release header."""
    result = set()
    for context, cell in _explicit_fixed_table_rows(page_html):
        release = _clean_fixed_cell(cell)
        context = _clean_context(context)
        if not release or not context:
            continue
        # Exclude non-release instructions; do not infer a patch from affected versions.
        if re.search(r'migrate|upgrade|contact|not affected|see|n/a', release, re.I):
            continue
        if _is_planned_release(context + ' ' + release):
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
    fixed = {x for x in fixed if not _is_planned_release(x) and not re.search(r'updated information|release notes', x, re.I)}
    return sorted(x for x in affected if versioned_name(x)), sorted(fixed), sorted(unresolved)



def clean_product_footnotes(value):
    """Strip only observed Cisco HTML superscript artifacts, not release digits.

    Applied to product names, never to version strings. Preserve numerals in
    actual product names (e.g. Webex 2, Catalyst 9300).
    """
    value = ' '.join(str(value or '').split())
    value = re.sub(r'(?i)(\bExpressway(?: Select)? Series)2$', r'\1', value)
    value = re.sub(r'(?i)(\bUltra-Reliable Wireless Backhaul \(URWB\))1,\s*2(?=\s)', r'\1', value)
    return value


def fixed_availability_audit(record):
    """Diagnostic only. Never claim a fix is available from a version string.

    A Cisco Software Checker result requires product/platform/current release;
    this advisory collector does not possess that inventory.
    """
    products = ' '.join(record.get('AffectedProduct') or [])
    checker = bool(re.search(
        r'\b(?:IOS(?: XE| XR)?|NX-OS|FXOS|ASA|FTD|FMC)\b|'
        r'Firewall (?:Threat Defense|Management Center)|Adaptive Security Appliance',
        products, re.I))
    if checker and not record.get('FixedVersion'):
        return 'SOFTWARE_CHECKER_REQUIRED_OR_FIX_NOT_EXTRACTED'
    if not record.get('FixedVersion'):
        return 'FIX_NOT_EXTRACTED_OR_NOT_PUBLISHED'
    return 'FIX_LISTED_AVAILABILITY_NOT_INDEPENDENTLY_VERIFIED'


def normalize_fixed_entries(entries):
    """Remove exact duplicates and *unambiguous* numeric footnote artifacts.

    Never collapse different product/trains or infer a newer fixed release.
    Example: 'Earlier than RI.2026.071' can be a footnote suffix only
    when an otherwise identical row already exists without the final '1'.
    """
    values = {' '.join(str(x).split()) for x in entries if str(x).strip()}
    normalized = set(values)
    for value in values:
        if ' -> ' not in value:
            continue
        context, fixed = value.split(' -> ', 1)
        if not context.endswith('1'):
            continue
        candidate = context[:-1] + ' -> ' + fixed
        if candidate in values and re.search(r'\bRI\.\d{4}\.\d{2}1$', context):
            normalized.discard(value)
    return sorted(normalized)


def product_names_from_fixed_context(entries):
    """Conservative fallback when the Cisco API/CSAF offers no family.

    Only product-labelled fixed-table rows qualify; numeric release trains,
    generic status labels and affected-version ranges do not.
    """
    names = set()
    for entry in entries:
        if ' -> ' not in entry:
            continue
        context, _ = entry.split(' -> ', 1)
        context = ' '.join(context.split())
        if (not re.search(r'[A-Za-z]{3}', context)
                or re.match(r'^(?:earlier than|prior to|before|all versions|release\s+\d)', context, re.I)
                or re.fullmatch(r'[\d.()a-zA-Z-]+', context)
                or re.search(r'\b(?:not affected|under investigation|fixed|vulnerable)\b', context, re.I)):
            continue
        # Footnote markers immediately preceding a whitespace-separated
        # product descriptor are removed, but embedded digits are retained.
        context = re.sub(r'(?<=\D)(?:1,2|1, 2)(?=\s)', '', context)
        names.add(context)
    return sorted(names)


def reconcile_record(record):
    """Post-enrichment cleanup; retains the exact public JSON schema."""
    record['FixedVersion'] = normalize_fixed_entries(record['FixedVersion'])
    # Normalize product labels on both sides of a mapping without altering
    # release numbers or treating an estimated future release as available.
    cleaned_fixed = []
    for entry in record['FixedVersion']:
        if ' -> ' in entry:
            context, release = entry.split(' -> ', 1)
            cleaned_fixed.append(clean_product_footnotes(context) + ' -> ' + release)
        else:
            cleaned_fixed.append(entry)
    record['FixedVersion'] = normalize_fixed_entries(cleaned_fixed)
    record['AffectedProduct'] = sorted(set(clean_product_footnotes(p) for p in record['AffectedProduct']))
    families = [p for p in record['AffectedProduct'] if p and p != 'NA']
    if not families:
        inferred = product_names_from_fixed_context(record['FixedVersion'])
        if inferred:
            record['AffectedProduct'] = inferred
    return record


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
    audit = []
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
        reconcile_record(record)
        output.append(record)
        audit.append({'AdvisoryKey': record['AdvisoryKey'],
                      'FixedVersionAssessment': fixed_availability_audit(record),
                      'CiscoAdvisoryURL': record['URL']})
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
    (BASE / 'cisco_fixed_version_audit.json').write_text(
        json.dumps(audit, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    ET.indent(rss, space='  ')
    ET.ElementTree(rss).write(BASE / 'cisco_enriched.xml', encoding='utf-8', xml_declaration=True)
    print(f'Collected {len(output)} Cisco advisories; wrote JSON and RSS')
    print('FixedVersion is not proof of release availability. See cisco_fixed_version_audit.json for review flags.')
    print('With fixed releases:', sum(bool(x['FixedVersion']) for x in output))
    print('With affected releases:', sum(bool(x['AffectedVersions']) for x in output))
    print('Severity counts:', {s: sum(x['Severity'] == s for x in output) for s in sorted(set(x['Severity'] for x in output))})


if __name__ == '__main__':
    main()
