"""
Network Discovery Functions
Enhanced with MAC OUI detection, concurrent ping sweep, and Linux support
"""

from __future__ import annotations

import socket
import subprocess
import platform
import re
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import config
from . import network_os


def ping_ip(ip: str, timeout_ms: int = 600) -> bool:
    """Ping a host. Cross-platform."""
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
        kwargs = {
            "startupinfo": _win_hidden_startupinfo(),
            "creationflags": subprocess.CREATE_NO_WINDOW,
        }
    else:
        timeout_sec = max(1, timeout_ms // 1000)
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
        kwargs = {}

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            **kwargs,
            shell=False,
            timeout=timeout_sec + 1 if "windows" not in system else 5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _win_hidden_startupinfo():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = subprocess.SW_HIDE
    return si


def guess_device_type(ip: str, hostname: str, mac: Optional[str] = None) -> str:
    """
    Detect device type using (in priority order):
    1. MAC OUI vendor database
    2. Hostname heuristics
    3. IP heuristics
    Returns a descriptive string like "Apple iPhone/Mac", "Cisco Router", etc.
    """
    if mac:
        vendor = config.lookup_vendor(mac)
        if vendor:
            device_cat = config.VENDOR_TO_DEVICE.get(vendor)
            if device_cat:
                return device_cat
            return f"{vendor} Device"

    h = (hostname or "").lower()

    if any(k in h for k in ("iphone", "ipad", "ipod", "mac", "macbook", "apple")):
        return "Apple Device"
    if any(k in h for k in ("galaxy", "samsung", "sm-")):
        return "Samsung Device"
    if any(k in h for k in ("redmi", "xiaomi", "miui")):
        return "Xiaomi/Redmi"
    if any(k in h for k in ("huawei", "honor")):
        return "Huawei Device"
    if any(k in h for k in ("android", "pixel")):
        return "Android Phone"
    if any(k in h for k in ("laptop", "notebook")):
        return "Laptop"
    if any(k in h for k in ("desktop", "workstation")):
        return "Desktop PC"
    if any(k in h for k in ("pc-", "-pc", "computer")):
        return "Computer"
    if any(k in h for k in ("printer", "print", "hp-")):
        return "Printer"
    if any(k in h for k in ("tv", "smarttv", "firetv", "chromecast", "shield")):
        return "Smart TV"
    if any(k in h for k in ("router", "gateway", "ap-", "access-point")):
        return "Router / AP"
    if any(k in h for k in ("nas", "synology", "qnap", "storage")):
        return "NAS / Storage"
    if any(k in h for k in ("pi", "raspberry")):
        return "Raspberry Pi"
    if any(k in h for k in ("alexa", "echo", "amazon")):
        return "Amazon Echo"
    if any(k in h for k in ("nest", "google-home")):
        return "Google Home / Nest"
    if any(k in h for k in ("cam", "camera", "ipcam", "nvr", "dvr")):
        return "IP Camera / NVR"
    if any(k in h for k in ("iot", "sensor", "esp", "arduino", "wemos")):
        return "IoT Device"

    if ip.endswith(".1") or ip.endswith(".254"):
        return "Router / Gateway"

    return "Unknown Device"


def discover_hosts_concurrent(
    subnet_prefix: str,
    progress_callback=None,
    stop_event=None,
) -> List[Dict[str, str]]:
    """
    Fast concurrent ping sweep + ARP table scan.
    progress_callback(current, total) called every batch.
    stop_event: threading.Event to cancel early.
    """
    hosts: List[Dict[str, str]] = []
    known_ips = set()
    total = 254

    def check_ip(last_octet: int) -> Optional[Dict[str, str]]:
        if stop_event and stop_event.is_set():
            return None
        ip = f"{subnet_prefix}.{last_octet}"
        if ping_ip(ip, timeout_ms=600):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"
            mac = config.get_mac_for_ip(ip)
            ttl = network_os.get_ttl(ip, timeout_ms=700)
            os_guess = network_os.fingerprint_os_from_ttl(ttl)
            return {
                "ip": ip,
                "hostname": hostname,
                "mac": mac or "",
                "type": guess_device_type(ip, hostname, mac),
                "os_guess": os_guess,
            }
        return None

    batch_size = 32
    completed = 0
    with ThreadPoolExecutor(max_workers=batch_size) as ex:
        futures = {ex.submit(check_ip, i): i for i in range(1, 255)}
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                hosts.append(result)
                known_ips.add(result["ip"])
            if progress_callback and completed % 16 == 0:
                progress_callback(completed, total)

    if progress_callback:
        progress_callback(total, total)

    try:
        sys = platform.system().lower()
        cmd = ["arp", "-a"]
        kwargs: dict = {}
        if "windows" in sys:
            kwargs = {
                "startupinfo": _win_hidden_startupinfo(),
                "creationflags": subprocess.CREATE_NO_WINDOW,
            }
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10,
            **kwargs,
        )
        arp_ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", result.stdout)
        for ip in arp_ips:
            if not ip.startswith(subnet_prefix + "."):
                continue
            if ip in known_ips:
                continue
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = "Unknown"
            mac = config.get_mac_for_ip(ip)
            ttl = network_os.get_ttl(ip, timeout_ms=700)
            os_guess = network_os.fingerprint_os_from_ttl(ttl)
            hosts.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": mac or "",
                    "type": guess_device_type(ip, hostname, mac),
                    "os_guess": os_guess,
                }
            )
            known_ips.add(ip)
    except Exception:
        pass

    hosts.sort(key=lambda h: int(h["ip"].split(".")[-1]))
    return hosts


def get_default_gateway_subnet_prefix() -> Optional[str]:
    """Get subnet prefix (e.g. '192.168.1') from default gateway. Cross-platform."""
    system = platform.system().lower()
    try:
        if "windows" in system:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                startupinfo=_win_hidden_startupinfo(),
                creationflags=subprocess.CREATE_NO_WINDOW,
                shell=False,
            )
            gateways = re.findall(r"Default Gateway[^\:]*:\s*([\d\.]*)", result.stdout)
        else:
            try:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="ignore",
                    timeout=5,
                )
                if result.returncode == 0:
                    match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
                    gateways = [match.group(1)] if match else []
                else:
                    gateways = []
            except (FileNotFoundError, subprocess.TimeoutExpired):
                try:
                    result = subprocess.run(
                        ["route", "-n", "get", "default"],
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="ignore",
                        timeout=5,
                    )
                    if result.returncode == 0:
                        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", result.stdout)
                        gateways = [match.group(1)] if match else []
                    else:
                        gateways = []
                except Exception:
                    gateways = []

        gateways = [g.strip() for g in gateways if g.strip() and g.strip() not in ("", "0.0.0.0")]
        if not gateways:
            return None

        parts = gateways[0].split(".")
        if len(parts) != 4:
            return None
        return ".".join(parts[:3])
    except Exception:
        return None


def get_local_ip() -> Optional[str]:
    """Get this machine's local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None

