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


def versioned_name(name):
    """True only for an explicit release identifier; family names stay out of versions."""
    return bool(re.search(r'(?<![A-Za-z])\d+\.\d+(?:\.\d+)*(?:\s*(?:Patch|p)\s*\d+)?\b', name, re.I))


def product_families(csaf):
    """Read actual CSAF product-family nodes, not product-tree release leaves."""
    families = set()

    def walk(branch):
        if branch.get('category') in ('product_family', 'product_name'):
            name = str(branch.get('name') or '').strip()
            if name and not versioned_name(name):
                families.add(name)
        for child in branch.get('branches') or []:
