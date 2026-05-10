from __future__ import annotations

import platform
import re
import subprocess
from typing import Optional


TTL_RE = re.compile(r"ttl[=\s:]+(\d+)", re.IGNORECASE)


def get_ttl(ip: str, timeout_ms: int = 800) -> Optional[int]:
    sys = platform.system().lower()
    if "windows" in sys:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), ip]
        kwargs = {}
        try:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = si
        except Exception:
            pass
        timeout = 4
    else:
        timeout_s = max(1, int(timeout_ms // 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip]
        kwargs = {}
        timeout = timeout_s + 1

    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            shell=False,
            **kwargs,
        )
    except Exception:
        return None

    out = (res.stdout or "") + "\n" + (res.stderr or "")
    m = TTL_RE.search(out)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def fingerprint_os_from_ttl(ttl: Optional[int]) -> str:
    if ttl is None:
        return ""
    if ttl <= 0:
        return ""
    if ttl <= 70:
        return "Linux/Unix (TTL~64)"
    if ttl <= 140:
        return "Windows (TTL~128)"
    if ttl <= 200:
        return "Network/Appliance (TTL~255?)"
    return "Network/Appliance (TTL~255)"

