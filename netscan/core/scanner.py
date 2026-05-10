"""
Port Scanning and Vulnerability Detection
Enhanced with better banner grabbing and service fingerprinting
"""

from __future__ import annotations

import socket
import ssl
import re
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .. import config


def get_service_banner(sock: socket.socket, port: int, ip: str) -> str:
    """Grab service banner / version string."""
    try:
        sock.settimeout(2.0)

        if port == 22:  # SSH
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                if "SSH" in banner:
                    return banner.strip()[:120]
            except Exception:
                pass

        elif port == 21:  # FTP
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                return banner.strip()[:120]
            except Exception:
                pass

        elif port == 80:  # HTTP
            try:
                req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                resp = sock.recv(4096).decode("utf-8", errors="ignore")
                for line in resp.split("\n"):
                    if "Server:" in line:
                        return line.strip()[:120]
                return resp.split("\n")[0].strip()[:80]
            except Exception:
                pass

        elif port == 8080:  # HTTP Alt
            try:
                req = f"GET / HTTP/1.1\r\nHost: {ip}:8080\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                resp = sock.recv(4096).decode("utf-8", errors="ignore")
                for line in resp.split("\n"):
                    if "Server:" in line:
                        return line.strip()[:120]
                return resp.split("\n")[0].strip()[:80]
            except Exception:
                pass

        elif port == 443:  # HTTPS
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                    tls.settimeout(2.0)
                    req = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                    tls.send(req.encode())
                    resp = tls.recv(4096).decode("utf-8", errors="ignore")
                    for line in resp.split("\n"):
                        if "Server:" in line:
                            return line.strip()[:120]
                    cipher = tls.cipher()
                    if cipher:
                        return f"TLS: {cipher[0]} / {cipher[1]}"
            except Exception:
                return "HTTPS (TLS)"

        elif port == 25:  # SMTP
            try:
                banner = sock.recv(1024).decode("utf-8", errors="ignore")
                return banner.strip()[:120]
            except Exception:
                pass

        elif port == 3306:  # MySQL
            try:
                data = sock.recv(1024)
                if len(data) > 5:
                    raw = data[5:].split(b"\x00")[0]
                    version = raw.decode("utf-8", errors="ignore")
                    return f"MySQL {version}"
            except Exception:
                pass

        elif port == 5900:  # VNC
            try:
                banner = sock.recv(256).decode("utf-8", errors="ignore")
                if "RFB" in banner:
                    return banner.strip()[:80]
            except Exception:
                pass

        elif port == 3389:  # RDP
            try:
                sock.recv(256)
                return "RDP Service Detected"
            except Exception:
                return "RDP Service Detected"

        elif port == 1883:  # MQTT
            try:
                connect = (
                    b"\x10\x0d"
                    b"\x00\x04MQTT"
                    b"\x04"
                    b"\x02"
                    b"\x00\x3c"
                    b"\x00\x00"
                )
                sock.send(connect)
                resp = sock.recv(64)
                if len(resp) >= 4 and resp[0] == 0x20:
                    rc = resp[3]
                    if rc == 0:
                        return "MQTT OK (no auth required — INSECURE)"
                    return f"MQTT CONNACK rc={rc}"
            except Exception:
                pass

        elif port == 9200:  # Elasticsearch
            try:
                req = f"GET / HTTP/1.1\r\nHost: {ip}:9200\r\nConnection: close\r\n\r\n"
                sock.send(req.encode())
                resp = sock.recv(2048).decode("utf-8", errors="ignore")
                m = re.search(r'"number"\s*:\s*"([^"]+)"', resp)
                if m:
                    return f"Elasticsearch {m.group(1)}"
                return resp.split("\n")[0].strip()[:80]
            except Exception:
                pass

        elif port == 27017:  # MongoDB
            try:
                msg = (
                    b"\x41\x00\x00\x00"
                    b"\x01\x00\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"\xd4\x07\x00\x00"
                    b"\x00\x00\x00\x00"
                    b"admin.$cmd\x00"
                    b"\x00\x00\x00\x00"
                    b"\x01\x00\x00\x00"
                    b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
                )
                sock.send(msg)
                resp = sock.recv(1024)
                if b"maxWireVersion" in resp or b"ismaster" in resp.lower():
                    return "MongoDB (responding to isMaster)"
            except Exception:
                pass
    except Exception:
        pass
    return ""


def scan_port(ip: str, port: int, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """Scan a single TCP port (IPv4 or IPv6)."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        addr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        if sock.connect_ex(addr) == 0:
            banner = get_service_banner(sock, port, ip)
            return {
                "port": port,
                "service": config.COMMON_PORTS.get(port, "Unknown"),
                "banner": banner,
            }
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return None


def scan_host(ip: str, ports: List[int], timeout: float = 1.0, max_workers: int = 64) -> List[Dict[str, Any]]:
    """Scan multiple ports concurrently."""
    open_ports: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, ip, p, timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports, key=lambda x: x["port"])


def check_vulnerabilities(ip: str, port: int, service: str, banner: str = "") -> List[Dict[str, Any]]:
    """Return known vulnerabilities for the given port/service/banner."""
    vulns: List[Dict[str, Any]] = []

    if port in config.VULNERABILITIES:
        for v in config.VULNERABILITIES[port]:
            vulns.append(
                {
                    "port": port,
                    "name": v["name"],
                    "severity": v["severity"],
                    "strength": v.get("strength", "Unknown"),
                    "description": v.get("description", ""),
                    "impact": v.get("impact", "Potential security risk"),
                    "recommendation": v.get("recommendation", "Review and secure this service"),
                    "service": service,
                }
            )

    if banner:
        bl = banner.lower()

        if port == 445 and ("smb" in bl or "samba" in bl):
            if any(ver in bl for ver in ["1.0", "2.0", "3.0"]):
                vulns.append(
                    {
                        "port": port,
                        "name": "Old SMB Version",
                        "severity": "High",
                        "strength": "Strong",
                        "description": f"Old SMB version detected: {banner[:60]}",
                        "impact": "Older SMB versions are easier to exploit",
                        "recommendation": "Update SMB and disable SMBv1",
                        "service": service,
                    }
                )

        if port == 3389 and "rdp" in bl:
            vulns.append(
                {
                    "port": port,
                    "name": "RDP Service Exposed",
                    "severity": "High",
                    "strength": "Strong",
                    "description": "RDP service detected on default port",
                    "impact": "High-value target for brute-force and exploitation",
                    "recommendation": "Enable NLA, use strong passwords, consider changing port",
                    "service": service,
                }
            )

        if port == 1883 and "no auth" in bl:
            vulns.append(
                {
                    "port": port,
                    "name": "MQTT Unauthenticated",
                    "severity": "Critical",
                    "strength": "Very Weak",
                    "description": "MQTT broker accepts connections without credentials",
                    "impact": "Anyone can subscribe/publish to all IoT topics",
                    "recommendation": "Enable MQTT authentication immediately",
                    "service": service,
                }
            )

        if port == 3306 and "mysql" in bl:
            m = re.search(r"(\d+\.\d+)", banner)
            if m:
                try:
                    ver = float(m.group(1))
                except Exception:
                    ver = 999.0
                if ver < 8.0:
                    vulns.append(
                        {
                            "port": port,
                            "name": f"MySQL Outdated Version ({m.group(1)})",
                            "severity": "Medium",
                            "strength": "Medium",
                            "description": f"MySQL {m.group(1)} has known vulnerabilities",
                            "impact": "Known CVEs may allow privilege escalation or data exposure",
                            "recommendation": "Upgrade to MySQL 8.0 or later",
                            "service": service,
                        }
                    )

    return vulns


def parse_ports(text: str) -> List[int]:
    """Parse a ports string to a list. Empty/'all' → common ports."""
    ports_text = (text or "").strip().lower()
    if not ports_text or ports_text == "all":
        return list(config.COMMON_PORTS.keys())

    ports: List[int] = []
    for part in ports_text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                for p in range(int(lo), int(hi) + 1):
                    if 1 <= p <= 65535:
                        ports.append(p)
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                pass

    return list(dict.fromkeys(ports))

