from __future__ import annotations

import datetime as _dt
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from ..core.models import ScanResult


def _env() -> Environment:
    templates_dir = Path(__file__).parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def render_html(result: ScanResult) -> str:
    env = _env()
    tpl = env.get_template("report.html")
    hosts = []
    vuln_total = 0
    for h in result.hosts:
        d = asdict(h)
        vuln_total += len(d.get("vulnerabilities") or [])
        hosts.append(d)
    return tpl.render(
        generated_at=_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        subnet=(result.subnet_prefix + ".0/24") if result.subnet_prefix else "—",
        host_count=len(result.hosts),
        ports=",".join(map(str, result.ports[:64])) + ("…" if len(result.ports) > 64 else ""),
        vuln_total=vuln_total,
        hosts=hosts,
    )


def save_html(result: ScanResult, path: str) -> str:
    html = render_html(result)
    Path(path).write_text(html, encoding="utf-8")
    return path


def save_pdf(result: ScanResult, path: str) -> str:
    c = canvas.Canvas(path, pagesize=letter)
    _width, height = letter
    x = 0.7 * inch
    y = height - 0.8 * inch

    def line(txt: str, dy: float = 14):
        nonlocal y
        if y < 0.8 * inch:
            c.showPage()
            y = height - 0.8 * inch
        c.drawString(x, y, txt[:140])
        y -= dy

    line("NetScan Report", dy=20)
    line(f"Generated: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if result.subnet_prefix:
        line(f"Subnet: {result.subnet_prefix}.0/24")
    line(f"Hosts: {len(result.hosts)}")
    line(f"Ports: {','.join(map(str, result.ports[:32]))}" + ("…" if len(result.ports) > 32 else ""))
    line("")

    for h in result.hosts:
        line("=" * 90)
        line(f"{h.ip}  {h.hostname}")
        line(
            f"MAC: {h.mac or '—'}  Type: {h.device_type}  OS: {h.os_guess or '—'}  "
            f"Trust: {'Rogue' if h.is_rogue else 'Trusted'}"
        )
        if h.open_ports:
            line("Open ports:")
            for p in h.open_ports[:50]:
                line(f"  - {p.proto.upper()} {p.port} {p.service}  {p.banner}")
        else:
            line("Open ports: none")
        if h.vulnerabilities:
            line("Vulnerabilities:")
            for v in h.vulnerabilities[:80]:
                cve = f"{v.cve_id} " if v.cve_id else ""
                line(f"  - [{v.severity}] {cve}{v.name} ({v.source})")
        else:
            line("Vulnerabilities: none")
        if h.web_findings:
            line("HTTP discovery:")
            for scheme, items in (h.web_findings or {}).items():
                if not items:
                    continue
                line(f"  {scheme.upper()}:")
                for it in items[:20]:
                    line(f"    - {it.get('status')} {it.get('url')}")
        line("")

    c.save()
    return path


def scanresult_from_dict(d: Dict[str, Any]) -> ScanResult:
    raise NotImplementedError("Not used yet")

