from __future__ import annotations

from typing import Dict, List, Optional

import requests


DEFAULT_HTTP_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
]


def check_http_basic_auth(
    url: str,
    creds: Optional[List[tuple[str, str]]] = None,
    timeout: float = 3.0,
) -> List[Dict[str, str]]:
    """
    Guardrailed: tries a tiny set of defaults, only once each, no brute force loops.
    Returns successful credentials if any.
    """
    creds = creds or list(DEFAULT_HTTP_CREDS)
    hits: List[Dict[str, str]] = []
    for user, pw in creds[:4]:
        try:
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                auth=(user, pw),
                headers={"User-Agent": "NetScan/2.0"},
            )
            if r.status_code in (200, 204):
                hits.append({"url": url, "username": user, "password": pw})
                break
        except Exception:
            continue
    return hits

