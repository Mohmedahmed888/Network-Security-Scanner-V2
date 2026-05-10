"""
QThread classes for background operations
"""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional

from PySide6.QtCore import QThread, Signal

from .. import config
from . import network, scanner
from .models import HostResult, PortFinding, ScanResult, VulnFinding
from ..storage.history_db import HistoryDB
from ..services import udp_scanner, http_discovery, cve_nvd, arp_guard


class DiscoverThread(QThread):
    done = Signal(str, list)  # subnet_prefix, hosts
    error = Signal(str)
    progress = Signal(int, int)  # current, total

    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        try:
            subnet = network.get_default_gateway_subnet_prefix()
            if not subnet:
                self.error.emit(
                    "Could not detect subnet prefix.\n"
                    "Check your network connection and try again."
                )
                return

            def prog(cur, tot):
                self.progress.emit(cur, tot)

            hosts = network.discover_hosts_concurrent(
                subnet,
                progress_callback=prog,
                stop_event=self._stop_event,
            )
            self.done.emit(subnet, hosts)
        except Exception as e:
            self.error.emit(str(e))


class ScanThread(QThread):
    log = Signal(str, str)  # message, color_key
    done = Signal()
    done_with_result = Signal(object)  # ScanResult
    error = Signal(str)
    progress = Signal(int, int)  # current, total

    def __init__(
        self,
        hosts: List[Dict[str, str]],
        ports: List[int],
        *,
        subnet_prefix: str = "",
        options: Optional[Dict[str, Any]] = None,
        db: Optional[HistoryDB] = None,
    ):
        super().__init__()
        self.hosts = hosts
        self.ports = ports
        self.subnet_prefix = subnet_prefix
        self.options = options or {}
        self.db = db or HistoryDB()
        self.last_result: Optional[ScanResult] = None

    def run(self):
        try:
            total = len(self.hosts)
            total_vulns = 0
            scan_result = ScanResult(
                scan_type="portscan",
                subnet_prefix=self.subnet_prefix or "",
                ports=list(self.ports),
                options=dict(self.options),
                hosts=[],
            )
            scan_id = self.db.create_scan(
                "portscan",
                subnet_prefix=self.subnet_prefix or None,
                host_count=total,
                ports=self.ports,
                options=self.options,
            )

            self.log.emit("=" * 70, "header")
            self.log.emit("  NETWORK SECURITY SCAN REPORT", "title")
            self.log.emit("=" * 70, "header")
            self.log.emit("", "info")

            for idx, host in enumerate(self.hosts, 1):
                ip = host["ip"]
                hostname = host.get("hostname", "Unknown")
                dev_type = host.get("type", "Unknown")
                mac = host.get("mac", "")

                self.log.emit("=" * 70, "header")
                self.log.emit(f"  HOST #{idx}: {ip}", "success")
                self.log.emit(f"  Hostname  : {hostname}", "info")
                if mac:
                    self.log.emit(f"  MAC       : {mac}", "info")
                self.log.emit(f"  Device    : {dev_type}", "info")
                self.log.emit(f"  Scanning  : {len(self.ports)} port(s)...", "info")

                open_ports = scanner.scan_host(ip, self.ports, timeout=1.0, max_workers=64)
                udp_findings = []
                if bool(self.options.get("udp_scan")):
                    udp_ports = [53, 67, 68, 69, 123, 161, 500, 1900]
                    udp_findings = udp_scanner.scan_udp_host(ip, udp_ports, timeout=1.0)

                trust_status = "Trusted" if not config.is_rogue_device(ip) else "Rogue"
                color = "trusted" if trust_status == "Trusted" else "warning"
                self.log.emit(f"  Trust     : {trust_status}", color)
                self.log.emit("", "info")

                host_res = HostResult(
                    ip=ip,
                    hostname=hostname,
                    mac=mac or "",
                    device_type=dev_type or "Unknown",
                    os_guess=host.get("os_guess") or "",
                    is_rogue=bool(config.is_rogue_device(ip)),
                )
                host_db_id = self.db.add_host(
                    scan_id,
                    {"ip": ip, "hostname": hostname, "mac": mac, "type": dev_type, "os_guess": host_res.os_guess},
                    os_guess=host_res.os_guess,
                    is_rogue=1 if host_res.is_rogue else 0,
                )

                if not open_ports:
                    self.log.emit("  ✅ No open ports detected", "success")
                    self.log.emit("", "info")
                else:
                    self.log.emit(f"  ⚠  {len(open_ports)} open port(s) found:", "warning")
                    self.log.emit("", "info")

                    for p in open_ports:
                        port_num = p["port"]
                        service_name = p["service"]
                        banner = p.get("banner", "")

                        self.log.emit("-" * 70, "divider")
                        self.log.emit(f"  PORT {port_num}  ({service_name})", "port")

                        if banner:
                            self.log.emit(f"  Banner: {banner[:80]}", "info")

                        vulns = scanner.check_vulnerabilities(ip, port_num, service_name, banner)
                        if vulns:
                            total_vulns += len(vulns)
                            self.log.emit(f"  🔴 {len(vulns)} vulnerability(ies) found:", "error")
                            self.log.emit("", "info")

                            for i, vuln in enumerate(vulns, 1):
                                sev_color = {
                                    "Critical": "critical",
                                    "High": "error",
                                    "Medium": "warning",
                                    "Low": "advice",
                                }.get(vuln["severity"], "warning")

                                strength = vuln.get("strength", "Unknown")
                                s_icon = (
                                    "🔥"
                                    if "Very Strong" in strength or strength == "Strong"
                                    else "⚡"
                                    if "Weak" in strength
                                    else "⚠️"
                                )

                                self.log.emit(f"  [{i}] {vuln['name']}", sev_color)
                                self.log.emit(
                                    f"      Severity : {vuln['severity']} | Exploitability: {s_icon} {strength}",
                                    sev_color,
                                )
                                self.log.emit(f"      What     : {vuln.get('description', '')}", "info")
                                self.log.emit(f"      Impact   : {vuln.get('impact', '')}", "warning")
                                self.log.emit(f"      Fix      : {vuln.get('recommendation', '')}", "advice")
                                if i < len(vulns):
                                    self.log.emit("", "info")

                                vf = VulnFinding(
                                    name=vuln["name"],
                                    severity=vuln.get("severity", "Unknown"),
                                    source="static",
                                    port=port_num,
                                    proto="tcp",
                                    description=vuln.get("description", "") or "",
                                    recommendation=vuln.get("recommendation", "") or "",
                                    extra={
                                        "strength": vuln.get("strength", "Unknown"),
                                        "impact": vuln.get("impact", ""),
                                        "service": service_name,
                                    },
                                )
                                host_res.vulnerabilities.append(vf)
                                self.db.add_vuln(
                                    host_db_id,
                                    name=vf.name,
                                    severity=vf.severity,
                                    port=port_num,
                                    proto="tcp",
                                    source=vf.source,
                                    cve_id=vf.cve_id,
                                    score=vf.score,
                                    description=vf.description,
                                    recommendation=vf.recommendation,
                                    extra=vf.extra,
                                )
                        else:
                            advice = config.get_advice_for_port(port_num)
                            self.log.emit("  ✅ Status: No known critical vulnerabilities", "trusted")
                            self.log.emit(f"  📌 Note  : {advice}", "advice")

                        nvd_items = []
                        if banner:
                            try:
                                nvd_items = cve_nvd.lookup_cves_for_banner(self.db, service_name, banner, max_results=5)
                            except Exception:
                                nvd_items = []
                        if nvd_items:
                            self.log.emit(f"  🧠 NVD: {len(nvd_items)} CVE(s) matched (best-effort)", "warning")
                            for it in nvd_items:
                                sev_color = {
                                    "Critical": "critical",
                                    "High": "error",
                                    "Medium": "warning",
                                    "Low": "advice",
                                }.get(it.get("severity") or "Unknown", "warning")
                                cve_id = it.get("cve_id") or it.get("name") or "CVE"
                                self.log.emit(
                                    f"    - {cve_id}  [{it.get('severity','Unknown')}]  score={it.get('score','?')}",
                                    sev_color,
                                )
                                vf = VulnFinding(
                                    name=it.get("name") or cve_id,
                                    severity=it.get("severity") or "Unknown",
                                    source="nvd",
                                    port=port_num,
                                    proto="tcp",
                                    cve_id=cve_id,
                                    score=it.get("score"),
                                    description=it.get("description") or "",
                                    recommendation="Check vendor advisory / apply patches and mitigations.",
                                )
                                host_res.vulnerabilities.append(vf)
                                self.db.add_vuln(
                                    host_db_id,
                                    name=vf.name,
                                    severity=vf.severity,
                                    port=port_num,
                                    proto="tcp",
                                    source=vf.source,
                                    cve_id=vf.cve_id,
                                    score=vf.score,
                                    description=vf.description,
                                    recommendation=vf.recommendation,
                                )

                        pf = PortFinding(
                            proto="tcp",
                            port=int(port_num),
                            service=service_name or "Unknown",
                            banner=banner or "",
                        )
                        host_res.open_ports.append(pf)
                        self.db.add_open_port(
                            host_db_id,
                            proto="tcp",
                            port=int(port_num),
                            service=pf.service,
                            banner=pf.banner,
                        )
                        self.log.emit("", "info")

                if udp_findings:
                    self.log.emit(f"  🟠 UDP findings: {len(udp_findings)} (best-effort)", "warning")
                    for uf in udp_findings:
                        port_num = int(uf["port"])
                        status = uf.get("status", "open|filtered")
                        pf = PortFinding(
                            proto="udp",
                            port=port_num,
                            service="UDP",
                            banner=status,
                            meta={"response": uf.get("response", "")},
                        )
                        host_res.open_ports.append(pf)
                        self.db.add_open_port(
                            host_db_id,
                            proto="udp",
                            port=port_num,
                            service="UDP",
                            banner=status,
                            meta=pf.meta,
                        )
                    self.log.emit("", "info")

                if bool(self.options.get("http_discovery")):
                    web = {}
                    has80 = any(pf.proto == "tcp" and pf.port == 80 for pf in host_res.open_ports)
                    has443 = any(pf.proto == "tcp" and pf.port == 443 for pf in host_res.open_ports)
                    if has80:
                        web["http"] = http_discovery.discover_paths(f"http://{ip}", timeout=2.0, max_workers=8)
                    if has443:
                        web["https"] = http_discovery.discover_paths(f"https://{ip}", timeout=2.5, max_workers=8)
                    if web:
                        host_res.web_findings = web
                        self.log.emit("  🟡 HTTP discovery:", "advice")
                        for scheme, items in web.items():
                            if not items:
                                continue
                            self.log.emit(f"    {scheme.upper()} found {len(items)} path(s):", "info")
                            for it in items[:12]:
                                self.log.emit(f"      {it['status']}  {it['url']}", "info")
                        self.log.emit("", "info")

                scan_result.hosts.append(host_res)
                self.progress.emit(idx, total)

            self.log.emit("", "info")
            self.log.emit("=" * 70, "header")
            self.log.emit("  SCAN SUMMARY", "title")
            self.log.emit("=" * 70, "header")
            self.log.emit("", "info")

            if total_vulns > 0:
                self.log.emit(f"  🔴 Total Vulnerabilities : {total_vulns}", "error")
                self.log.emit(f"  🖥  Hosts Scanned        : {total}", "info")
                self.log.emit("  ⚡ ACTION REQUIRED: Review and patch vulnerabilities!", "critical")
                self.log.emit("  Priority: HIGH — Immediate action recommended", "error")
            else:
                self.log.emit("  ✅ No vulnerabilities detected", "success")
                self.log.emit(f"  🖥  Hosts Scanned: {total}", "info")
                self.log.emit("  🛡  Network appears secure — continue regular monitoring", "trusted")

            self.log.emit("", "info")
            self.log.emit("=" * 70, "header")
            self.last_result = scan_result
            self.done_with_result.emit(scan_result)
            self.done.emit()
        except Exception as e:
            self.error.emit(str(e))


class MonitorThread(QThread):
    new_device = Signal(object)  # host dict
    arp_change = Signal(str, str, str)  # ip, old_mac, new_mac
    status = Signal(str)
    error = Signal(str)

    def __init__(
        self,
        subnet_prefix: str,
        *,
        interval_s: int = 45,
        db: Optional[HistoryDB] = None,
    ):
        super().__init__()
        self.subnet_prefix = subnet_prefix
        self.interval_s = max(10, int(interval_s))
        self.db = db or HistoryDB()
        self._stop = threading.Event()
        self._known_ips: set[str] = set()
        self._prev_arp: Dict[str, str] = {}

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            self.status.emit(f"Monitoring every {self.interval_s}s…")
            try:
                hosts = network.discover_hosts_concurrent(self.subnet_prefix, progress_callback=None, stop_event=self._stop)
                self._known_ips = {h.get('ip', '') for h in (hosts or []) if h.get('ip')}
                self._prev_arp = arp_guard.read_arp_table()
            except Exception:
                self._prev_arp = arp_guard.read_arp_table()

            while not self._stop.is_set():
                self._stop.wait(self.interval_s)
                if self._stop.is_set():
                    break

                arp_map = arp_guard.read_arp_table()
                curr_ips = set(arp_map.keys())
                new_ips = [ip for ip in curr_ips if ip.startswith(self.subnet_prefix + ".") and ip not in self._known_ips]
                for ip in new_ips:
                    host = {"ip": ip, "mac": arp_map.get(ip, ""), "hostname": "Unknown", "type": "Unknown"}
                    self._known_ips.add(ip)
                    self.new_device.emit(host)
                    try:
                        self.db.add_alert("new_device", f"New device detected: {ip}", ip=ip, mac=host.get("mac") or "")
                    except Exception:
                        pass

                try:
                    changes = arp_guard.detect_spoof_changes(self._prev_arp, arp_map)
                    for ip, (old_mac, new_mac) in changes.items():
                        if not ip.startswith(self.subnet_prefix + "."):
                            continue
                        self.arp_change.emit(ip, old_mac, new_mac)
                        try:
                            self.db.add_alert(
                                "arp_change",
                                f"ARP change detected for {ip}: {old_mac} -> {new_mac}",
                                ip=ip,
                                mac=new_mac,
                                extra={"old_mac": old_mac},
                            )
                        except Exception:
                            pass
                except Exception:
                    pass

                self._prev_arp = arp_map
        except Exception as e:
            self.error.emit(str(e))

