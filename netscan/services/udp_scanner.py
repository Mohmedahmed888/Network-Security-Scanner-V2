from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional


def _udp_probe(ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    payload = b""
    if port == 53:
        payload = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    elif port == 123:
        payload = b"\x1b" + (47 * b"\0")
    elif port == 1900:
        payload = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 1\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        if payload:
            s.sendto(payload, (ip, port))
        else:
            s.sendto(b"", (ip, port))
        try:
            data, _addr = s.recvfrom(2048)
            return {
                "port": port,
                "status": "open",
                "response": (data[:120].decode("utf-8", errors="ignore") if data else ""),
            }
        except socket.timeout:
            return {"port": port, "status": "open|filtered", "response": ""}
        except Exception:
            return {"port": port, "status": "open|filtered", "response": ""}
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def scan_udp_host(ip: str, ports: List[int], timeout: float = 1.0) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for p in ports:
        r = _udp_probe(ip, int(p), float(timeout))
        if r:
            findings.append(r)
    return findings

