from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _default_data_dir(app_name: str = "NetScan") -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / app_name
    return Path.home() / ".local" / "share" / app_name


def default_db_path() -> Path:
    data_dir = _default_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "netscan.db"


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  scan_type TEXT NOT NULL,
  subnet_prefix TEXT,
  host_count INTEGER DEFAULT 0,
  ports TEXT,
  options_json TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  ip TEXT NOT NULL,
  mac TEXT,
  hostname TEXT,
  device_type TEXT,
  os_guess TEXT,
  is_rogue INTEGER DEFAULT 0,
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS open_ports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  proto TEXT NOT NULL,
  port INTEGER NOT NULL,
  service TEXT,
  banner TEXT,
  meta_json TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id INTEGER NOT NULL,
  port INTEGER,
  proto TEXT,
  source TEXT,
  cve_id TEXT,
  name TEXT NOT NULL,
  severity TEXT,
  score REAL,
  description TEXT,
  recommendation TEXT,
  extra_json TEXT,
  FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  alert_type TEXT NOT NULL,
  ip TEXT,
  mac TEXT,
  message TEXT NOT NULL,
  extra_json TEXT
);

CREATE TABLE IF NOT EXISTS cve_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  cache_key TEXT NOT NULL UNIQUE,
  payload_json TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class ScanRow:
    id: int
    created_at: int
    scan_type: str
    subnet_prefix: Optional[str]
    host_count: int
    ports: Optional[str]
    options: Dict[str, Any]


class HistoryDB:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._apply_schema()

    def close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def _apply_schema(self):
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def create_scan(
        self,
        scan_type: str,
        subnet_prefix: Optional[str] = None,
        host_count: int = 0,
        ports: Optional[Iterable[int]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> int:
        ts = int(time.time())
        ports_str = ",".join(map(str, ports)) if ports else None
        opt_json = json.dumps(options or {}, ensure_ascii=False)
        cur = self._conn.execute(
            "INSERT INTO scans(created_at, scan_type, subnet_prefix, host_count, ports, options_json) "
            "VALUES(?,?,?,?,?,?)",
            (ts, scan_type, subnet_prefix, host_count, ports_str, opt_json),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def add_host(
        self,
        scan_id: int,
        host: Dict[str, Any],
        os_guess: Optional[str] = None,
        is_rogue: int = 0,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO hosts(scan_id, ip, mac, hostname, device_type, os_guess, is_rogue) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                scan_id,
                host.get("ip"),
                host.get("mac") or None,
                host.get("hostname") or None,
                host.get("type") or host.get("device_type") or None,
                os_guess or host.get("os_guess") or None,
                int(is_rogue),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def add_open_port(
        self,
        host_id: int,
        proto: str,
        port: int,
        service: Optional[str] = None,
        banner: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ):
        self._conn.execute(
            "INSERT INTO open_ports(host_id, proto, port, service, banner, meta_json) "
            "VALUES(?,?,?,?,?,?)",
            (
                host_id,
                proto,
                int(port),
                service,
                banner,
                json.dumps(meta or {}, ensure_ascii=False),
            ),
        )
        self._conn.commit()

    def add_vuln(
        self,
        host_id: int,
        name: str,
        severity: Optional[str] = None,
        port: Optional[int] = None,
        proto: Optional[str] = None,
        source: str = "static",
        cve_id: Optional[str] = None,
        score: Optional[float] = None,
        description: Optional[str] = None,
        recommendation: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        self._conn.execute(
            "INSERT INTO vulns(host_id, port, proto, source, cve_id, name, severity, score, description, recommendation, extra_json) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                host_id,
                port,
                proto,
                source,
                cve_id,
                name,
                severity,
                score,
                description,
                recommendation,
                json.dumps(extra or {}, ensure_ascii=False),
            ),
        )
        self._conn.commit()

    def add_alert(
        self,
        alert_type: str,
        message: str,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        ts = int(time.time())
        self._conn.execute(
            "INSERT INTO alerts(created_at, alert_type, ip, mac, message, extra_json) "
            "VALUES(?,?,?,?,?,?)",
            (ts, alert_type, ip, mac, message, json.dumps(extra or {}, ensure_ascii=False)),
        )
        self._conn.commit()

    def list_scans(self, limit: int = 100) -> List[ScanRow]:
        cur = self._conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC, id DESC LIMIT ?",
            (int(limit),),
        )
        rows: List[ScanRow] = []
        for r in cur.fetchall():
            try:
                options = json.loads(r["options_json"] or "{}")
            except Exception:
                options = {}
            rows.append(
                ScanRow(
                    id=int(r["id"]),
                    created_at=int(r["created_at"]),
                    scan_type=str(r["scan_type"]),
                    subnet_prefix=r["subnet_prefix"],
                    host_count=int(r["host_count"] or 0),
                    ports=r["ports"],
                    options=options,
                )
            )
        return rows

    def get_scan_hosts(self, scan_id: int) -> List[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM hosts WHERE scan_id=? ORDER BY ip",
            (int(scan_id),),
        )
        return [dict(r) for r in cur.fetchall()]

    def get_host_ports(self, host_id: int) -> List[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM open_ports WHERE host_id=? ORDER BY proto, port",
            (int(host_id),),
        )
        ports = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["meta"] = json.loads(d.get("meta_json") or "{}")
            except Exception:
                d["meta"] = {}
            ports.append(d)
        return ports

    def get_host_vulns(self, host_id: int) -> List[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT * FROM vulns WHERE host_id=? ORDER BY severity DESC, id ASC",
            (int(host_id),),
        )
        vulns = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["extra"] = json.loads(d.get("extra_json") or "{}")
            except Exception:
                d["extra"] = {}
            vulns.append(d)
        return vulns

    def cache_get(self, cache_key: str, max_age_seconds: int) -> Optional[Dict[str, Any]]:
        cur = self._conn.execute(
            "SELECT created_at, payload_json FROM cve_cache WHERE cache_key=?",
            (cache_key,),
        )
        row = cur.fetchone()
        if not row:
            return None
        created_at = int(row["created_at"])
        if int(time.time()) - created_at > int(max_age_seconds):
            return None
        try:
            return json.loads(row["payload_json"])
        except Exception:
            return None

    def cache_put(self, cache_key: str, payload: Dict[str, Any]):
        ts = int(time.time())
        payload_json = json.dumps(payload, ensure_ascii=False)
        self._conn.execute(
            "INSERT INTO cve_cache(created_at, cache_key, payload_json) VALUES(?,?,?) "
            "ON CONFLICT(cache_key) DO UPDATE SET created_at=excluded.created_at, payload_json=excluded.payload_json",
            (ts, cache_key, payload_json),
        )
        self._conn.commit()

