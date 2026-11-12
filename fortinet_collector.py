
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import feedparser
import requests
from bs4 import BeautifulSoup

RSS_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
OUTPUT_FILE = Path("fortinet_advisories.json")
MAX_ITEMS = 20

session = requests.Session()
session.headers.update({
    "User-Agent": "VendorSecurityAdvisoryCollector/1.0",
    "Accept": "text/html,application/xhtml+xml"
})


def clean(value):
    return re.sub(r"\s+", " ", value or "").strip()


def get_advisory(url):
    result = {
        "AffectedProduct": [],
        "AffectedVersions": [],
        "FixedVersion": [],
        "CVE": [],
        "Severity": "Unknown",
        "ExtractionStatus": "Unverified"
    }

    parsed = urlparse(url)
    if parsed.hostname != "fortiguard.fortinet.com":
        raise ValueError("Unexpected advisory domain")

    response = session.get(url, timeout=20)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    text = soup.get_text(" ", strip=True)

    result["CVE"] = sorted(set(
        re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)
    ))

    for severity in ("Critical", "High", "Medium", "Low"):
        if re.search(r"\bSeverity\s*:?\s*" + severity + r"\b",
                     text, re.I):
            result["Severity"] = severity.upper()
            break

    # Extract only explicitly labelled version-table rows.
    for table in soup.find_all("table"):
        headers = [
            clean(th.get_text(" ", strip=True)).lower()
            for th in table.find_all("th")
        ]

        if not {"version", "affected", "solution"}.issubset(set(headers)):
            continue

        for row in table.find_all("tr"):
            cells = row.find_all("td")
            if len(cells) < 3:
                continue

            values = [clean(c.get_text(" ", strip=True))
                      for c in cells]

            product, affected, fixed = values[:3]

            if product and affected:
                result["AffectedProduct"].append(product)
                result["AffectedVersions"].append(
                    {"Product": product, "Versions": affected}
                )
                result["FixedVersion"].append(
                    {"Product": product, "Solution": fixed}
                )

    if result["AffectedVersions"]:
        result["ExtractionStatus"] = "Version table extracted"
    else:
        result["ExtractionStatus"] = "Version table not found"

    return result


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
            "CollectedAt": datetime.now(timezone.utc).isoformat()
        }

        try:
            record.update(get_advisory(url))
        except Exception as exc:
            record["ExtractionStatus"] = "Failed"
            record["ExtractionError"] = str(exc)

        advisories.append(record)

    OUTPUT_FILE.write_text(
        json.dumps(advisories, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    print(f"Collected {len(advisories)} advisories")
    print(f"Output: {OUTPUT_FILE}")

    for item in advisories:
        print(
            item["Title"],
            "|",
            item["ExtractionStatus"]
        )


if __name__ == "__main__":
    main()

