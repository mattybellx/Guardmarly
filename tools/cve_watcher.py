#!/usr/bin/env python3
"""CVE Watcher — fetches new CVEs from NVD and creates GitHub issues for
vulnerabilities in languages supported by Ansede Static.

Usage:
    python -m tools.cve_watcher --languages python,go,java --days 7
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SUPPORTED_LANGS = {
    "python", "javascript", "typescript", "go", "java", "csharp", "ruby", "php",
}

CWE_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def fetch_recent_cves(days: int = 7) -> list[dict]:
    """Fetch CVEs modified in the last N days from NVD."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)

    params = urllib.parse.urlencode({
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "100",
    })

    url = f"{NVD_API}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "ansede-cve-watcher/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        print(f"Error fetching NVD data: {exc}", file=sys.stderr)
        return []

    return data.get("vulnerabilities", [])


def cwe_from_cve(cve_item: dict) -> str | None:
    """Extract primary CWE from a CVE item."""
    for weakness in cve_item.get("cve", {}).get("weaknesses", []):
        for desc in weakness.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                return desc["value"]
    return None


def relevant_cves(cve_items: list[dict], languages: set[str]) -> list[dict]:
    """Filter CVEs to those relevant to supported languages."""
    relevant = []
    for item in cve_items:
        cve_data = item.get("cve", {})
        description = ""

        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Check if description mentions a supported language
        desc_lower = description.lower()
        for lang in languages:
            if lang in desc_lower or _lang_keywords(lang, desc_lower):
                relevant.append({
                    "cve_id": cve_data.get("id", "UNKNOWN"),
                    "description": description[:300],
                    "cwe": cwe_from_cve(item),
                    "language": lang,
                    "published": cve_data.get("published", ""),
                    "severity": _extract_severity(item),
                })
                break
    return relevant


def _lang_keywords(lang: str, text: str) -> bool:
    """Check for language-specific keywords in text."""
    keywords = {
        "python": ["flask", "django", "fastapi", "pip", "pypi", "python"],
        "javascript": ["node.js", "express", "npm", "react", "vue", "angular"],
        "go": ["golang", "go module", "go package"],
        "java": ["spring", "maven", "gradle", "jakarta", "jvm"],
        "csharp": [".net", "asp.net", "nuget", "c#", "dotnet"],
        "ruby": ["rails", "ruby gem", "rack", "sinatra"],
        "php": ["laravel", "symfony", "composer", "wordpress", "drupal"],
    }
    return any(kw in text for kw in keywords.get(lang, []))


def _extract_severity(item: dict) -> str:
    """Extract CVSS severity from a CVE item."""
    try:
        metrics = item.get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in metrics.get(key, []):
                sev = metric.get("cvssData", {}).get("baseSeverity", "")
                if sev:
                    return CWE_SEVERITY.get(sev, "medium")
    except Exception:
        pass
    return "medium"


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE Watcher for Ansede Static")
    parser.add_argument("--languages", default="python,javascript,go,java,csharp",
                        help="Comma-separated list of languages to watch")
    parser.add_argument("--days", type=int, default=7,
                        help="Look back N days for CVEs")
    parser.add_argument("--output", default="tools/new_cves.json",
                        help="Output JSON file path")
    args = parser.parse_args()

    languages = {l.strip().lower() for l in args.languages.split(",")}
    languages &= SUPPORTED_LANGS

    if not languages:
        print("No supported languages specified.", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching CVEs from last {args.days} days for: {', '.join(sorted(languages))}")

    cve_items = fetch_recent_cves(args.days)
    relevant = relevant_cves(cve_items, languages)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(relevant, indent=2))

    print(f"Found {len(relevant)} relevant CVEs out of {len(cve_items)} total")
    for cve in relevant:
        print(f"  {cve['cve_id']} [{cve['language']}] {cve['cwe'] or 'N/A'}: {cve['description'][:120]}")


if __name__ == "__main__":
    main()
