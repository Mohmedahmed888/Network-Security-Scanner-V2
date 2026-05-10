from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PortFinding:
    proto: str  # tcp|udp
    port: int
    service: str = "Unknown"
    banner: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VulnFinding:
    name: str
    severity: str = "Unknown"
    source: str = "static"  # static|nvd|heuristic
    port: Optional[int] = None
    proto: Optional[str] = None
    cve_id: Optional[str] = None
    score: Optional[float] = None
    description: str = ""
    recommendation: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    hostname: str = "Unknown"
    mac: str = ""
    device_type: str = "Unknown"
    os_guess: str = ""
    is_rogue: bool = False
    open_ports: List[PortFinding] = field(default_factory=list)
    vulnerabilities: List[VulnFinding] = field(default_factory=list)
    web_findings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    scan_type: str  # discovery|portscan|monitor
    subnet_prefix: str = ""
    ports: List[int] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    hosts: List[HostResult] = field(default_factory=list)

