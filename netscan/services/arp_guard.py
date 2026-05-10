from __future__ import annotations

import platform
import re
import subprocess
from typing import Dict, Tuple


MAC_RE = re.compile(
    r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})"
)
IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")


def read_arp_table() -> Dict[str, str]:
    sys = platform.system().lower()
    cmd = ["arp", "-a"]
    kwargs = {}
    if "windows" in sys:
        try:
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = si
        except Exception:
            pass

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            **kwargs,
        )
    except Exception:
        return {}

    mapping: Dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        ipm = IP_RE.search(line)
        macm = MAC_RE.search(line)
        if not ipm or not macm:
            continue
        ip = ipm.group(1)
        mac = macm.group(1).lower().replace("-", ":")
        if mac != "00:00:00:00:00:00":
            mapping[ip] = mac
    return mapping


def detect_spoof_changes(prev: Dict[str, str], curr: Dict[str, str]) -> Dict[str, Tuple[str, str]]:
    changes: Dict[str, Tuple[str, str]] = {}
    for ip, new_mac in curr.items():
        old = prev.get(ip)
        if old and old != new_mac:
            changes[ip] = (old, new_mac)
    return changes

