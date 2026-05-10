from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..storage.history_db import HistoryDB


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _api_key() -> Optional[str]:
    return os.environ.get("NVD_API_KEY") or os.environ.get("NVD_API_TOKEN")


def _banner_to_query(service: str, banner: str) -> Optional[str]:
    b = (banner or "").strip()
    s = (service or "").strip()
    low = (b + " " + s).lower()

    patterns: List[Tuple[str, str]] = [
        (r"openssh[_\-\s]?(\d+(\.\d+)+)", "OpenSSH \\1"),
        (r"apache/?(\d+(\.\d+)+)", "Apache HTTP Server \\1"),
        (r"nginx/?(\d+(\.\d+)+)", "nginx \\1"),
        (r"vsftpd\s+(\d+(\.\d+)+)", "vsftpd \\1"),
        (r"samba\s+(\d+(\.\d+)+)", "Samba \\1"),
        (r"mysql\s+(\d+(\.\d+)+)", "MySQL \\1"),
        (r"elasticsearch\s+(\d+(\.\d+)+)", "Elasticsearch \\1"),
    ]
    for rx, repl in patterns:
        m = re.search(rx, low, re.IGNORECASE)
        if m:
            return re.sub(rx, repl, low, flags=re.IGNORECASE)

    for k in ("ssh", "http", "https", "ftp", "smb", "rdp", "mqtt", "mongodb", "elasticsearch", "mysql"):
        if k in low:
            return k
    return None


def _normalize_severity(cvss: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    score = None
    sev = "Unknown"
    try:
        score = float(cvss.get("baseScore")) if cvss.get("baseScore") is not None else None
    except Exception:
        score = None
    if score is None:
        return sev, None
    if score >= 9.0:
        return "Critical", score
    if score >= 7.0:
        return "High", score
    if score >= 4.0:
        return "Medium", score
    return "Low", score


def fetch_cves_keyword(keyword: str, *, max_results: int = 5, timeout: float = 8.0) -> Dict[str, Any]:
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": str(int(max_results)),
        "startIndex": "0",
    }
    headers = {}
    key = _api_key()
    if key:
        headers["apiKey"] = key
    r = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def lookup_cves_for_banner(
    db: HistoryDB,
    service: str,
    banner: str,
    *,
    cache_ttl_seconds: int = 7 * 24 * 3600,
    max_results: int = 5,
) -> List[Dict[str, Any]]:
    q = _banner_to_query(service, banner)
    if not q:
        return []

    cache_key = f"nvd:kw:{q}"
    cached = db.cache_get(cache_key, max_age_seconds=cache_ttl_seconds)
    if cached:
        return cached.get("items", []) or []

    try:
        payload = fetch_cves_keyword(q, max_results=max_results)
    except Exception:
        return []

    items: List[Dict[str, Any]] = []
    for v in (payload.get("vulnerabilities") or [])[:max_results]:
        cve = (v.get("cve") or {})
        cve_id = cve.get("id") or ""
        desc = ""
        for d in (cve.get("descriptions") or []):
            if d.get("lang") == "en":
                desc = d.get("value") or ""
                break

        metrics = (cve.get("metrics") or {})
        cvss = None
        if metrics.get("cvssMetricV31"):
            cvss = metrics["cvssMetricV31"][0].get("cvssData") or {}
        elif metrics.get("cvssMetricV30"):
            cvss = metrics["cvssMetricV30"][0].get("cvssData") or {}
        elif metrics.get("cvssMetricV2"):
            cvss = metrics["cvssMetricV2"][0].get("cvssData") or {}

        sev, score = _normalize_severity(cvss or {})
        items.append(
            {
                "cve_id": cve_id,
                "name": cve_id,
                "severity": sev,
                "score": score,
                "description": desc[:2000],
                "source": "nvd",
            }
        )

    db.cache_put(cache_key, {"items": items, "fetched_at": int(time.time()), "query": q})
    return items

