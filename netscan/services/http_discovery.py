from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import requests


DEFAULT_PATHS = [
    "/admin",
    "/login",
    "/administrator",
    "/wp-admin",
    "/phpmyadmin",
    "/setup",
    "/dashboard",
]


def _check_url(url: str, timeout: float) -> Optional[Tuple[str, int, str]]:
    try:
        r = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "NetScan/2.0"},
        )
        ct = (r.headers.get("content-type") or "").split(";")[0].strip()
        return (url, int(r.status_code), ct)
    except Exception:
        return None


def discover_paths(
    base_url: str,
    paths: Optional[List[str]] = None,
    timeout: float = 2.0,
    max_workers: int = 8,
) -> List[Dict[str, str]]:
    base = base_url.rstrip("/")
    paths = paths or list(DEFAULT_PATHS)
    urls = [base + p for p in paths]
    found: List[Dict[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_check_url, u, timeout): u for u in urls}
        for f in as_completed(futs):
            res = f.result()
            if not res:
                continue
            url, code, ct = res
            if code in (200, 301, 302, 401, 403):
                found.append({"url": url, "status": str(code), "content_type": ct})
    return sorted(found, key=lambda x: x["url"])

