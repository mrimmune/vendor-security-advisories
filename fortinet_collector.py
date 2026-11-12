import json
import re
from datetime import datetime, timezone
from email.utils import format_datetime
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree as ET

import feedparser
import requests
from bs4 import BeautifulSoup

RSS_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
JSON_FILE = Path("fortinet_advisories.json")
XML_FILE = Path("fortinet_enriched.xml")
MAX_ITEMS = 20

session = requests.Session()
session.headers.update({
    "User-Agent": "VendorSecurityAdvisoryCollector/1.0",
    "Accept": "text/html,application/xhtml+xml,application/rss+xml",
})


def clean(value):
    return re.sub(r"\s+", " ", str(value or "")).strip()


def get_advisory(url):
    result = {
        "AffectedProduct": [],
        "AffectedVersions": [],
        "FixedVersion": [],
        "CVE": [],
        "Severity": "Unknown",
        "ExtractionStatus": "Unverified",
    }
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "fortiguard.fortinet.com":
        raise ValueError("Unexpected advisory URL")
    response = session.get(url, timeout=25)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    text = soup.get_text(" ", strip=True)
    result["CVE"] = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)))
    for severity in ("Critical", "High", "Medium", "Low"):
        if re.search(r"\bSeverity\s*:?\s*" + severity + r"\b", text, re.I):
            result["Severity"] = severity.upper()
            break
    for table in soup.find_all("table"):
        headers = [clean(th.get_text(" ", strip=True)).lower() for th in table.find_all("th")]
        if not {"version", "affected", "solution"}.issubset(set(headers)):
            continue
        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) < 3:
                continue
            product, affected, fixed = [clean(c.get_text(" ", strip=True)) for c in cells[:3]]
            if not product or not affected or affected.casefold() in ("not affected", "not applicable", "n/a"):
                continue
            if product not in result["AffectedProduct"]:
                result["AffectedProduct"].append(product)
            result["AffectedVersions"].append({"Product": product, "Versions": affected})
            result["FixedVersion"].append({"Product": product, "Solution": fixed})
    result["ExtractionStatus"] = (
        "Version table extracted" if result["AffectedVersions"] else "Version table not found"
    )
    return result


def make_rss(advisories):
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    for tag, value in (
        ("title", "Fortinet PSIRT Enriched Advisories"),
        ("link", "https://fortiguard.fortinet.com/psirt"),
        ("description", "Fortinet PSIRT advisories enriched with affected and fixed versions"),
        ("language", "en"),
        ("lastBuildDate", format_datetime(datetime.now(timezone.utc))),
    ):
        ET.SubElement(channel, tag).text = value

    for record in advisories:
        # Do not publish incomplete extraction as verified affected-version data.
        if record.get("ExtractionStatus") != "Version table extracted":
            continue
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = record["Title"]
        ET.SubElement(item, "link").text = record["URL"]
        ET.SubElement(item, "guid", {"isPermaLink": "true"}).text = record["URL"]
        if record.get("PublishedDate"):
            ET.SubElement(item, "pubDate").text = record["PublishedDate"]
        # Standard RSS description carries a JSON object for predictable parsing.
        description = {
            "Severity": record["Severity"],
            "CVE": record["CVE"],
            "AffectedProduct": record["AffectedProduct"],
            "AffectedVersions": record["AffectedVersions"],
            "FixedVersion": record["FixedVersion"],
            "ExtractionStatus": record["ExtractionStatus"],
        }
        ET.SubElement(item, "description").text = json.dumps(description, ensure_ascii=False, separators=(",", ":"))
    tree = ET.ElementTree(rss)
    ET.indent(tree, space="  ")
    tree.write(XML_FILE, encoding="utf-8", xml_declaration=True)


def main():
    response = session.get(RSS_URL, timeout=30)
    response.raise_for_status()
    feed = feedparser.parse(response.content)
    if feed.bozo and not feed.entries:
        raise RuntimeError("Unable to parse Fortinet RSS")
    advisories = []
    for entry in feed.entries[:MAX_ITEMS]:
        url = entry.get("link", "")
        if not url:
            continue
        record = {
            "Vendor": "Fortinet",
            "Title": clean(entry.get("title", "")),
            "URL": url,
            "PublishedDate": entry.get("published", ""),
            "CollectedAt": datetime.now(timezone.utc).isoformat(),
        }
        try:
            record.update(get_advisory(url))
        except Exception as exc:
            record["ExtractionStatus"] = "Failed"
            record["ExtractionError"] = str(exc)
        advisories.append(record)
    JSON_FILE.write_text(json.dumps(advisories, indent=2, ensure_ascii=False), encoding="utf-8")
    make_rss(advisories)
    print(f"Collected {len(advisories)} advisories")
    print(f"Version tables extracted: {sum(a.get('ExtractionStatus') == 'Version table extracted' for a in advisories)}")
    print(f"Created {JSON_FILE} and {XML_FILE}")


if __name__ == "__main__":
    main()
