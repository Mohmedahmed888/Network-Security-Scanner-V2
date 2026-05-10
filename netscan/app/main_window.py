from __future__ import annotations

import datetime
import platform
from typing import Dict, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QTextCharFormat
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QMainWindow,
)

from .. import config
from ..alerts.desktop import DesktopNotifier
from ..alerts.email import EmailAlert
from ..alerts.telegram import TelegramAlert
from ..core import network, scanner
from ..core.threads import DiscoverThread, MonitorThread, ScanThread
from ..reporting.report_generator import save_html, save_pdf
from ..storage.history_db import HistoryDB


C = {
    "bg_deep": "#070b12",
    "bg_main": "#0d1117",
    "bg_card": "#131a24",
    "bg_input": "#0f1923",
    "border": "#1e2d3d",
    "border_hi": "#00d4ff",
    "text": "#c9d1d9",
    "text_muted": "#6e7681",
    "accent": "#00d4ff",
    "accent2": "#7c3aed",
    "green": "#3fb950",
    "orange": "#f78166",
    "red": "#ff4d4d",
    "yellow": "#d29922",
    "white": "#ffffff",
    "critical": "#ff0055",
    "port": "#79c0ff",
}


STYLE = f"""
QMainWindow, QWidget {{
    background: {C['bg_main']};
    color: {C['text']};
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
}}
QFrame#header_frame {{
    background: {C['bg_card']};
    border-bottom: 2px solid {C['border_hi']};
}}
QFrame#section_card {{
    background: {C['bg_card']};
    border: 1px solid {C['border']};
    border-radius: 8px;
}}
QPushButton {{
    background: {C['bg_card']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 9px 16px;
    color: {C['text']};
    font-weight: 600;
    font-size: 12px;
}}
QPushButton:hover {{
    border: 1px solid {C['accent']};
    color: {C['accent']};
    background: {C['bg_input']};
}}
QPushButton#btn_primary {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #005f73, stop:1 #0096c7);
    border: 1px solid {C['accent']};
    color: {C['white']};
    font-weight: 700;
}}
QPushButton#btn_danger {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #3d0000, stop:1 #7d0000);
    border: 1px solid {C['red']};
    color: {C['orange']};
    font-weight: 700;
}}
QPushButton#btn_stop {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #3d1a00, stop:1 #7d3500);
    border: 1px solid {C['yellow']};
    color: {C['yellow']};
    font-weight: 700;
}}
QLineEdit, QComboBox, QSpinBox {{
    background: {C['bg_input']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 8px 12px;
    color: {C['text']};
    font-size: 12px;
}}
QTableWidget {{
    background: {C['bg_main']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    color: {C['text']};
}}
QTextEdit {{
    background: {C['bg_deep']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    color: {C['text']};
    padding: 12px;
    font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
    font-size: 12px;
}}
QProgressBar {{
    border: 1px solid {C['border']};
    border-radius: 5px;
    background: {C['bg_deep']};
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 {C['accent2']}, stop:0.5 {C['accent']}, stop:1 {C['green']});
    border-radius: 4px;
}}
"""


LOG_COLORS = {
    "info": C["text"],
    "success": C["green"],
    "warning": C["orange"],
    "error": C["red"],
    "critical": C["critical"],
    "trusted": C["green"],
    "advice": C["yellow"],
    "header": C["border_hi"],
    "title": C["white"],
    "divider": "#2a3a4a",
    "port": C["port"],
}


def icon_for_device_type(device_type: str) -> str:
    t = (device_type or "").lower()
    if "apple" in t:
        return "🍎"
    if "samsung" in t:
        return "📱"
    if "xiaomi" in t or "redmi" in t:
        return "📱"
    if "huawei" in t:
        return "📱"
    if "android" in t or "iphone" in t:
        return "📱"
    if "laptop" in t:
        return "💻"
    if "desktop" in t or "pc" in t:
        return "🖥️"
    if "router" in t or "gateway" in t:
        return "🌐"
    if "printer" in t:
        return "🖨️"
    return "❓"


def tbl_item(text: str, center: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    if center:
        it.setTextAlignment(Qt.AlignCenter)
    return it


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ NetScan — Advanced Network Security Scanner")
        self.resize(1360, 860)
        self.setMinimumSize(1000, 660)

        self.subnet_prefix: Optional[str] = None
        self.discovered_hosts: List[Dict] = []
        self._discover_thread: Optional[DiscoverThread] = None
        self._scan_thread: Optional[ScanThread] = None
        self._monitor_thread: Optional[MonitorThread] = None
        self._scan_start_time: Optional[datetime.datetime] = None

        self.db = HistoryDB()
        self.notifier = DesktopNotifier(self)
        self.tg = TelegramAlert()
        self.email = EmailAlert()
        self._last_scan_result = None

        self.setStyleSheet(STYLE)
        self._build_ui()
        self._detect_subnet_silent()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QFrame()
        header.setObjectName("header_frame")
        header.setFixedHeight(70)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 10, 20, 10)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        title_lbl = QLabel("⚡ NETSCAN")
        title_lbl.setStyleSheet(f"color:{C['accent']}; font-size:18px; font-weight:700; letter-spacing:2px;")
        sub_lbl = QLabel("ADVANCED NETWORK SECURITY MONITOR")
        sub_lbl.setStyleSheet(f"color:{C['text_muted']}; font-size:10px; letter-spacing:1px;")
        title_col.addWidget(title_lbl)
        title_col.addWidget(sub_lbl)

        info_col = QVBoxLayout()
        info_col.setSpacing(2)
        self.subnet_label = QLabel("Subnet: detecting…")
        self.subnet_label.setStyleSheet(f"color:{C['green']}; font-size:11px; font-weight:600;")
        self.device_count_label = QLabel("Devices: 0")
        self.device_count_label.setStyleSheet(f"color:{C['accent']}; font-size:11px; font-weight:600;")
        self.local_ip_label = QLabel(f"My IP: {network.get_local_ip() or '?'}")
        self.local_ip_label.setStyleSheet(f"color:{C['text_muted']}; font-size:11px;")
        info_col.addWidget(self.subnet_label)
        info_col.addWidget(QLabel(""))

        os_str = f"{platform.system()} {platform.release()}"
        os_lbl = QLabel(f"OS: {os_str}")
        os_lbl.setStyleSheet(f"color:{C['text_muted']}; font-size:11px;")

        self.status_badge = QLabel("Ready")
        self.status_badge.setAlignment(Qt.AlignCenter)
        self.status_badge.setMinimumWidth(120)
        self.status_badge.setStyleSheet(
            f"background:{C['bg_card']}; border:1px solid {C['border_hi']}; border-radius:10px; padding:4px 12px; color:{C['accent']}; font-size:11px; font-weight:600;"
        )

        hl.addLayout(title_col)
        hl.addSpacing(40)
        hl.addLayout(info_col)
        hl.addSpacing(20)
        hl.addWidget(self.device_count_label)
        hl.addSpacing(20)
        hl.addWidget(self.local_ip_label)
        hl.addSpacing(20)
        hl.addWidget(os_lbl)
        hl.addStretch(1)
        hl.addWidget(self.status_badge)
        layout.addWidget(header)

        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(12, 10, 12, 10)
        cl.setSpacing(8)

        toolbar = QFrame()
        toolbar.setObjectName("section_card")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(12, 8, 12, 8)
        tl.setSpacing(8)

        self.btn_discover = QPushButton("🔍  Scan Network")
        self.btn_discover.setObjectName("btn_primary")
        self.btn_discover.setMinimumHeight(38)
        self.btn_discover.clicked.connect(self.on_discover_clicked)

        self.btn_stop = QPushButton("⏹  Stop")
        self.btn_stop.setObjectName("btn_stop")
        self.btn_stop.setMinimumHeight(38)
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.on_stop_clicked)

        self.btn_scan_selected = QPushButton("🎯  Scan Selected")
        self.btn_scan_selected.setObjectName("btn_danger")
        self.btn_scan_selected.setMinimumHeight(38)
        self.btn_scan_selected.clicked.connect(self.on_scan_selected)

        self.btn_scan_all = QPushButton("🚀  Scan All")
        self.btn_scan_all.setObjectName("btn_danger")
        self.btn_scan_all.setMinimumHeight(38)
        self.btn_scan_all.clicked.connect(self.on_scan_all)

        self.btn_export = QPushButton("💾  Export")
        self.btn_export.setMinimumHeight(38)
        self.btn_export.clicked.connect(self.on_export_results)

        self.btn_monitor = QPushButton("🛰️  Monitor ON")
        self.btn_monitor.setMinimumHeight(38)
        self.btn_monitor.clicked.connect(self.on_toggle_monitor)

        self.btn_history = QPushButton("📜  History")
        self.btn_history.setMinimumHeight(38)
        self.btn_history.clicked.connect(self.on_open_history)

        self.btn_clear = QPushButton("🗑  Clear")
        self.btn_clear.setMinimumHeight(38)
        self.btn_clear.clicked.connect(self.on_clear_table)

        search_lbl = QLabel("🔎")
        self.search_entry = QLineEdit()
        self.search_entry.setPlaceholderText("Search devices (IP / hostname / type / MAC)...")
        self.search_entry.setMinimumHeight(38)
        self.search_entry.setMinimumWidth(260)
        self.search_entry.textChanged.connect(self.on_search_changed)

        tl.addWidget(self.btn_discover)
        tl.addWidget(self.btn_stop)
        tl.addSpacing(10)
        tl.addWidget(self.btn_scan_selected)
        tl.addWidget(self.btn_scan_all)
        tl.addSpacing(10)
        tl.addWidget(self.btn_export)
        tl.addWidget(self.btn_monitor)
        tl.addWidget(self.btn_history)
        tl.addWidget(self.btn_clear)
        tl.addStretch(1)
        tl.addWidget(search_lbl)
        tl.addWidget(self.search_entry)
        cl.addWidget(toolbar)

        opts = QFrame()
        opts.setObjectName("section_card")
        ol = QHBoxLayout(opts)
        ol.setContentsMargins(12, 8, 12, 8)
        ol.setSpacing(12)

        ports_lbl = QLabel("Ports:")
        ports_lbl.setMinimumWidth(50)

        self.ports_preset = QComboBox()
        self.ports_preset.setMinimumHeight(36)
        self.ports_preset.addItem("Common (default)", "")
        self.ports_preset.addItem("Web (80,443,8080,8443)", "80,443,8080,8443")
        self.ports_preset.addItem("Remote (22,23,3389,5900)", "22,23,3389,5900")
        self.ports_preset.addItem("DB (3306,5432,27017,9200)", "3306,5432,27017,9200")
        self.ports_preset.addItem("IoT (1883,8883,5683)", "1883,8883,5683")
        self.ports_preset.addItem("Custom...", "CUSTOM")
        self.ports_preset.currentIndexChanged.connect(self._on_preset_changed)
        self.ports_preset.setMinimumWidth(220)

        self.ports_entry = QLineEdit()
        self.ports_entry.setPlaceholderText("e.g. 22,80,443  or  1-1024  or leave blank for common ports")
        self.ports_entry.setMinimumHeight(36)

        timeout_lbl = QLabel("Timeout (s):")
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 10)
        self.timeout_spin.setValue(1)
        self.timeout_spin.setMinimumHeight(36)
        self.timeout_spin.setMinimumWidth(70)

        self.chk_ping_only = QCheckBox("Ping only (no port scan)")
        self.chk_show_rogue = QCheckBox("Highlight unknown devices")
        self.chk_show_rogue.setChecked(True)
        self.chk_udp = QCheckBox("Include UDP scan")
        self.chk_http = QCheckBox("HTTP path discovery")

        ol.addWidget(ports_lbl)
        ol.addWidget(self.ports_preset)
        ol.addWidget(self.ports_entry, 1)
        ol.addWidget(timeout_lbl)
        ol.addWidget(self.timeout_spin)
        ol.addSpacing(16)
        ol.addWidget(self.chk_ping_only)
        ol.addWidget(self.chk_show_rogue)
        ol.addWidget(self.chk_udp)
        ol.addWidget(self.chk_http)
        cl.addWidget(opts)

        prog_row = QHBoxLayout()
        prog_row.setSpacing(10)
        self.progress_label = QLabel("◼ Idle")
        self.progress_label.setMinimumWidth(200)
        self.progress_label.setStyleSheet(f"color:{C['text_muted']}; font-size:11px;")
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        prog_row.addWidget(self.progress_label)
        prog_row.addWidget(self.progress_bar, 1)
        cl.addLayout(prog_row)

        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(4)

        self.table = QTableWidget(0, 6)
        headers = ["IP Address", "MAC Address", "Hostname", "Device Type", "OS Guess", "Trust Status"]
        for i, h in enumerate(headers):
            it = QTableWidgetItem(h)
            it.setFlags(it.flags() & ~Qt.ItemIsEditable)
            self.table.setHorizontalHeaderItem(i, it)

        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setHighlightSections(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFont(QFont("Segoe UI Emoji", 12))

        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        hdr.setSectionResizeMode(1, QHeaderView.Interactive)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.Interactive)
        hdr.setSectionResizeMode(4, QHeaderView.Interactive)
        hdr.setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(3, 220)
        self.table.setColumnWidth(4, 160)
        self.table.setColumnWidth(5, 110)
        self.table.setMinimumHeight(220)
        self.table.verticalHeader().setDefaultSectionSize(40)
        self.table.doubleClicked.connect(self.on_row_double_clicked)

        splitter.addWidget(self.table)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText("  Network scan results will appear here...\n  Click '🔍 Scan Network' to discover devices.")
        self.output.setFont(QFont("JetBrains Mono", 11))
        self.output.setMinimumHeight(160)
        splitter.addWidget(self.output)

        splitter.setSizes([420, 340])
        cl.addWidget(splitter, 1)
        layout.addWidget(content, 1)

    def _on_preset_changed(self, _idx: int):
        val = self.ports_preset.currentData()
        if val == "CUSTOM":
            self.ports_entry.setEnabled(True)
            self.ports_entry.setFocus()
        elif val:
            self.ports_entry.setText(val)
            self.ports_entry.setEnabled(False)
        else:
            self.ports_entry.clear()
            self.ports_entry.setEnabled(True)

    def _detect_subnet_silent(self):
        subnet = network.get_default_gateway_subnet_prefix()
        if subnet:
            self.subnet_prefix = subnet
            self.subnet_label.setText(f"Subnet: {subnet}.0/24")

    def set_busy(self, busy: bool, status: str):
        self.status_badge.setText(status)
        self.btn_discover.setEnabled(not busy)
        self.btn_stop.setEnabled(busy)
        self.btn_scan_selected.setEnabled(not busy)
        self.btn_scan_all.setEnabled(not busy)
        self.btn_export.setEnabled(not busy)
        self.btn_history.setEnabled(not busy)
        self.btn_clear.setEnabled(not busy)

    def log(self, msg: str, color_key: str = "info"):
        cursor = self.output.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        color = LOG_COLORS.get(color_key, LOG_COLORS["info"])
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        font = QFont("JetBrains Mono", 11)
        if color_key == "title":
            font.setBold(True)
            font.setPointSize(13)
        elif color_key in ("header", "critical", "error", "port"):
            font.setBold(True)
        fmt.setFont(font)
        cursor.setCharFormat(fmt)
        cursor.insertText(msg + "\n")
        self.output.setTextCursor(cursor)
        self.output.ensureCursorVisible()

    def refresh_table(self, hosts: Optional[List[Dict]] = None):
        self.table.setRowCount(0)
        hosts_to_show = hosts if hosts is not None else self.discovered_hosts
        self.device_count_label.setText(f"Devices: {len(hosts_to_show)}/{len(self.discovered_hosts)}" if hosts is not None else f"Devices: {len(self.discovered_hosts)}")
        highlight_rogue = self.chk_show_rogue.isChecked()

        for host in hosts_to_show:
            ip = host["ip"]
            mac = host.get("mac", "")
            hostname = host.get("hostname", "Unknown")
            dev_type = host.get("type", "Unknown")
            os_guess = host.get("os_guess", "") or ""
            is_rogue = config.is_rogue_device(ip)
            trust = "Rogue" if is_rogue else "Trusted"

            icon = icon_for_device_type(dev_type)
            row = self.table.rowCount()
            self.table.insertRow(row)

            row_bg = QColor(C["bg_card"]) if (highlight_rogue and is_rogue) else None

            ip_item = tbl_item(f"  {icon}  {ip}")
            if row_bg:
                ip_item.setBackground(row_bg)
            self.table.setItem(row, 0, ip_item)

            mac_item = tbl_item(mac or "—")
            mac_item.setForeground(QColor(C["text_muted"]))
            if row_bg:
                mac_item.setBackground(row_bg)
            self.table.setItem(row, 1, mac_item)

            host_item = tbl_item(hostname)
            if row_bg:
                host_item.setBackground(row_bg)
            self.table.setItem(row, 2, host_item)

            type_item = tbl_item(dev_type)
            type_item.setForeground(QColor(C["accent"]))
            if row_bg:
                type_item.setBackground(row_bg)
            self.table.setItem(row, 3, type_item)

            os_item = tbl_item(os_guess or "—")
            os_item.setForeground(QColor(C["text_muted"]))
            if row_bg:
                os_item.setBackground(row_bg)
            self.table.setItem(row, 4, os_item)

            trust_item = tbl_item(trust, center=True)
            trust_item.setForeground(QColor(C["green"] if trust == "Trusted" else C["red"]))
            if row_bg:
                trust_item.setBackground(row_bg)
            self.table.setItem(row, 5, trust_item)

    def get_selected_hosts(self) -> List[Dict]:
        rows = {idx.row() for idx in self.table.selectionModel().selectedRows()}
        selected: List[Dict] = []
        for r in sorted(rows):
            ip_text = self.table.item(r, 0).text().strip()
            parts = ip_text.split()
            ip = parts[-1] if parts else ""
            hostname = self.table.item(r, 2).text()
            dev_type = self.table.item(r, 3).text()
            mac = self.table.item(r, 1).text()
            os_guess = self.table.item(r, 4).text() if self.table.item(r, 4) else ""
            if mac == "—":
                mac = ""
            selected.append({"ip": ip, "hostname": hostname, "type": dev_type, "mac": mac, "os_guess": "" if os_guess == "—" else os_guess})
        return selected

    def on_search_changed(self, text: str):
        q = text.strip().lower()
        if not q:
            self.refresh_table()
            return
        filtered = [
            h for h in self.discovered_hosts
            if (q in h["ip"].lower() or q in h.get("hostname", "").lower() or q in h.get("type", "").lower() or q in h.get("mac", "").lower())
        ]
        self.refresh_table(filtered)

    def on_row_double_clicked(self, index):
        row = index.row()
        ip_text = self.table.item(row, 0).text().strip()
        parts = ip_text.split()
        ip = parts[-1] if parts else ""
        hostname = self.table.item(row, 2).text()
        dev_type = self.table.item(row, 3).text()
        mac = self.table.item(row, 1).text()
        os_guess = self.table.item(row, 4).text() if self.table.item(row, 4) else ""
        if mac == "—":
            mac = ""
        host = {"ip": ip, "hostname": hostname, "type": dev_type, "mac": mac, "os_guess": "" if os_guess == "—" else os_guess}
        ports = scanner.parse_ports(self.ports_entry.text())
        if not ports:
            return
        self.start_scan([host], ports)

    def on_discover_clicked(self):
        self.output.clear()
        self.set_busy(True, "Scanning…")
        self.log("  Starting network discovery...", "info")
        self.log(f"  Platform: {platform.system()} {platform.release()}", "info")
        local = network.get_local_ip()
        if local:
            self.log(f"  Local IP: {local}", "info")
        self.log("", "info")

        self._discover_thread = DiscoverThread()
        self._discover_thread.done.connect(self.on_discover_done)
        self._discover_thread.error.connect(self.on_error)
        self._discover_thread.progress.connect(self.on_discover_progress)
        self._discover_thread.start()

    def on_stop_clicked(self):
        if self._discover_thread and self._discover_thread.isRunning():
            self._discover_thread.stop()
        if self._monitor_thread and self._monitor_thread.isRunning():
            self._monitor_thread.stop()
        self.set_busy(False, "Stopped")

    def on_discover_progress(self, current: int, total: int):
        pct = int(current / total * 100) if total else 0
        self.progress_bar.setValue(pct)
        self.progress_label.setText(f"◉ Scanning {current}/{total}")

    def on_discover_done(self, subnet: str, hosts: list):
        self.subnet_prefix = subnet
        self.subnet_label.setText(f"Subnet: {subnet}.0/24")
        self.discovered_hosts = hosts or []
        try:
            scan_id = self.db.create_scan("discovery", subnet_prefix=subnet, host_count=len(self.discovered_hosts), options={"source": "ui"})
            for h in self.discovered_hosts:
                self.db.add_host(scan_id, h, os_guess=h.get("os_guess") or "", is_rogue=1 if config.is_rogue_device(h.get("ip", "")) else 0)
        except Exception:
            pass

        if not self.discovered_hosts:
            self.log("  ⚠  No hosts discovered.", "warning")
        else:
            self.log(f"  ✅ Discovered {len(self.discovered_hosts)} device(s)", "success")
        self.refresh_table()
        self.set_busy(False, "Ready")
        self.progress_bar.setValue(0)
        self.progress_label.setText("◼ Idle")

    def on_scan_selected(self):
        if not self.discovered_hosts:
            QMessageBox.warning(self, "Warning", "No devices discovered yet.\nClick '🔍 Scan Network' first.")
            return
        selected = self.get_selected_hosts()
        if not selected:
            QMessageBox.warning(self, "Warning", "No rows selected.\nSelect device(s) first.")
            return
        if self.chk_ping_only.isChecked():
            QMessageBox.information(self, "Info", "Ping-only mode is on. Disable it to run a port scan.")
            return
        ports = scanner.parse_ports(self.ports_entry.text())
        if not ports:
            QMessageBox.critical(self, "Error", "No valid ports specified.")
            return
        self.start_scan(selected, ports)

    def on_scan_all(self):
        if not self.discovered_hosts:
            QMessageBox.warning(self, "Warning", "No devices discovered yet.\nClick '🔍 Scan Network' first.")
            return
        if self.chk_ping_only.isChecked():
            QMessageBox.information(self, "Info", "Ping-only mode is on. Disable it to run a port scan.")
            return
        ports = scanner.parse_ports(self.ports_entry.text())
        if not ports:
            QMessageBox.critical(self, "Error", "No valid ports specified.")
            return
        self.start_scan(self.discovered_hosts, ports)

    def start_scan(self, hosts: List[Dict], ports: List[int]):
        self.output.clear()
        self.set_busy(True, "Scanning ports…")
        self._scan_start_time = datetime.datetime.now()
        self.log(f"  🚀 Port scan started — {len(hosts)} device(s), {len(ports)} port(s) each", "info")
        self.log("", "info")

        self._scan_thread = ScanThread(
            hosts,
            ports,
            subnet_prefix=self.subnet_prefix or "",
            options={
                "timeout_s": int(self.timeout_spin.value()),
                "udp_scan": bool(self.chk_udp.isChecked()),
                "http_discovery": bool(self.chk_http.isChecked()),
            },
            db=self.db,
        )
        self._scan_thread.log.connect(self.log)
        self._scan_thread.done_with_result.connect(self._on_scan_result)
        self._scan_thread.done.connect(self.on_scan_done)
        self._scan_thread.error.connect(self.on_error)
        self._scan_thread.progress.connect(self.on_scan_progress)
        self._scan_thread.start()

    def _on_scan_result(self, result):
        self._last_scan_result = result

    def on_scan_progress(self, current: int, total: int):
        pct = int(current / total * 100) if total else 0
        self.progress_bar.setValue(pct)
        self.progress_label.setText(f"◉ Scanning device {current}/{total}")

    def on_scan_done(self):
        self.set_busy(False, "Done")
        self.progress_bar.setValue(0)
        self.progress_label.setText("◼ Idle")

    def on_clear_table(self):
        self.discovered_hosts = []
        self.table.setRowCount(0)
        self.device_count_label.setText("Devices: 0")
        self.output.clear()

    def on_export_results(self):
        text = self.output.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Warning", "No results to export. Run a scan first.")
            return
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        fname, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            f"netscan_report_{ts}.txt",
            "Text Files (*.txt);;HTML Files (*.html);;PDF Files (*.pdf);;All Files (*)",
        )
        if not fname:
            return
        try:
            lower = fname.lower()
            if lower.endswith(".html"):
                if not self._last_scan_result:
                    raise RuntimeError("Run a port scan first (to generate structured result).")
                save_html(self._last_scan_result, fname)
            elif lower.endswith(".pdf"):
                if not self._last_scan_result:
                    raise RuntimeError("Run a port scan first (to generate structured result).")
                save_pdf(self._last_scan_result, fname)
            else:
                with open(fname, "w", encoding="utf-8") as f:
                    f.write(text)
            QMessageBox.information(self, "Exported", f"Report saved to:\n{fname}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to export:\n{e}")

    def on_open_history(self):
        try:
            dlg = HistoryDialog(self, self.db)
            dlg.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open history:\n{e}")

    def on_toggle_monitor(self):
        if not (self.subnet_prefix or "").strip():
            self._detect_subnet_silent()
        if not (self.subnet_prefix or "").strip():
            QMessageBox.warning(self, "Warning", "Subnet not detected yet. Run discovery first.")
            return
        if self._monitor_thread and self._monitor_thread.isRunning():
            self._monitor_thread.stop()
            self._monitor_thread = None
            self.btn_monitor.setText("🛰️  Monitor ON")
            self.status_badge.setText("Ready")
            return

        self._monitor_thread = MonitorThread(self.subnet_prefix, interval_s=45, db=self.db)
        self._monitor_thread.new_device.connect(self._on_new_device)
        self._monitor_thread.arp_change.connect(self._on_arp_change)
        self._monitor_thread.error.connect(self.on_error)
        self._monitor_thread.start()
        self.btn_monitor.setText("🛰️  Monitor OFF")
        self.status_badge.setText("Monitoring…")

    def _on_new_device(self, host: dict):
        ip = host.get("ip", "")
        mac = host.get("mac", "")
        self.log(f"  🆕 New device detected: {ip}  {mac}", "warning")
        try:
            self.notifier.notify("NetScan", f"New device detected: {ip}\n{mac}".strip())
        except Exception:
            pass
        try:
            msg = f"New device detected: {ip}\n{mac}".strip()
            self.tg.send("NetScan Alert", msg)
            self.email.send("NetScan Alert", msg)
        except Exception:
            pass

    def _on_arp_change(self, ip: str, old_mac: str, new_mac: str):
        self.log(f"  ⚠️ ARP change: {ip}  {old_mac} -> {new_mac}", "critical")
        try:
            self.notifier.notify("NetScan (ARP alert)", f"{ip}\n{old_mac} -> {new_mac}")
        except Exception:
            pass
        try:
            msg = f"ARP change detected:\n{ip}\n{old_mac} -> {new_mac}"
            self.tg.send("NetScan ARP Alert", msg)
            self.email.send("NetScan ARP Alert", msg)
        except Exception:
            pass

    def on_error(self, msg: str):
        self.set_busy(False, "Error")
        self.log(f"  ❌ Error: {msg}", "error")
        QMessageBox.critical(self, "Error", msg)


class HistoryDialog(QMessageBox):
    def __init__(self, parent: QWidget, db: HistoryDB):
        super().__init__(parent)
        self.db = db
        self.setWindowTitle("NetScan History")
        self.setIcon(QMessageBox.Information)

        body = QWidget()
        layout = QVBoxLayout(body)

        self.scans_tbl = QTableWidget(0, 4)
        self.scans_tbl.setHorizontalHeaderLabels(["ID", "Type", "Created", "Hosts"])
        self.scans_tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.scans_tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.scans_tbl.setSelectionMode(QAbstractItemView.SingleSelection)
        self.scans_tbl.doubleClicked.connect(self._on_scan_selected)

        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setMinimumHeight(220)

        layout.addWidget(QLabel("Recent scans (double-click to view):"))
        layout.addWidget(self.scans_tbl, 1)
        layout.addWidget(QLabel("Details:"))
        layout.addWidget(self.details, 1)

        self.layout().addWidget(body, 0, 0, 1, self.layout().columnCount())

        self._load_scans()
        self.setStandardButtons(QMessageBox.Close)

    def _load_scans(self):
        scans = self.db.list_scans(limit=50)
        self.scans_tbl.setRowCount(0)
        for s in scans:
            row = self.scans_tbl.rowCount()
            self.scans_tbl.insertRow(row)
            created = datetime.datetime.fromtimestamp(s.created_at).strftime("%Y-%m-%d %H:%M:%S")
            self.scans_tbl.setItem(row, 0, QTableWidgetItem(str(s.id)))
            self.scans_tbl.setItem(row, 1, QTableWidgetItem(s.scan_type))
            self.scans_tbl.setItem(row, 2, QTableWidgetItem(created))
            self.scans_tbl.setItem(row, 3, QTableWidgetItem(str(s.host_count)))

    def _on_scan_selected(self, _index):
        rows = self.scans_tbl.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        scan_id = int(self.scans_tbl.item(row, 0).text())
        hosts = self.db.get_scan_hosts(scan_id)
        lines = [f"Scan #{scan_id} — hosts: {len(hosts)}", ""]
        for h in hosts[:200]:
            ip = h.get("ip", "")
            mac = h.get("mac") or ""
            hn = h.get("hostname") or "Unknown"
            dt = h.get("device_type") or "Unknown"
            os_guess = h.get("os_guess") or ""
            rogue = "Rogue" if int(h.get("is_rogue") or 0) else "Trusted"
            lines.append(f"- {ip}  {hn}  [{dt}]  {rogue}" + (f"  OS:{os_guess}" if os_guess else ""))
        if len(hosts) > 200:
            lines.append("")
            lines.append(f"... truncated ({len(hosts) - 200} more)")
        self.details.setPlainText("\n".join(lines))

