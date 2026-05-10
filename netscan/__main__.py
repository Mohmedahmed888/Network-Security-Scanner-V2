"""
NetScan — Advanced Network Security Scanner
Entry point with animated splash screen
By: Mohamed Ahmed
"""

import sys

from PySide6.QtCore import Qt, QTimer, QRect
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPen,
    QPixmap,
)
from PySide6.QtWidgets import QApplication, QSplashScreen

from .app.main_window import MainWindow


def create_app_icon(size: int = 256) -> QPixmap:
    pix = QPixmap(size, size)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setRenderHint(QPainter.SmoothPixmapTransform)

    # Background circle
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor("#005f73"))
    grad.setColorAt(1.0, QColor("#0096c7"))
    p.setBrush(QBrush(grad))
    p.setPen(Qt.NoPen)
    p.drawEllipse(4, 4, size - 8, size - 8)

    # Network rings
    cx, cy = size // 2, size // 2
    pen = QPen(QColor("#00d4ff"), max(2, size // 32))
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    for r in [size // 8, size // 5, size // 3]:
        p.drawArc(cx - r, cy - r, r * 2, r * 2, 30 * 16, 300 * 16)

    # Centre dot
    p.setBrush(QColor("#ffffff"))
    p.setPen(Qt.NoPen)
    dot = size // 14
    p.drawEllipse(cx - dot, cy - dot, dot * 2, dot * 2)

    p.end()
    return pix


def create_splash(size_w: int = 480, size_h: int = 300) -> QPixmap:
    pix = QPixmap(size_w, size_h)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)

    # Dark background
    grad = QLinearGradient(0, 0, size_w, size_h)
    grad.setColorAt(0.0, QColor("#070b12"))
    grad.setColorAt(1.0, QColor("#0d1117"))
    p.fillRect(0, 0, size_w, size_h, QBrush(grad))

    # Border glow
    pen = QPen(QColor("#00d4ff"), 2)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawRoundedRect(2, 2, size_w - 4, size_h - 4, 12, 12)

    # Inner subtle border
    pen2 = QPen(QColor("#1e2d3d"), 1)
    p.setPen(pen2)
    p.drawRoundedRect(8, 8, size_w - 16, size_h - 16, 8, 8)

    # Logo
    logo = create_app_icon(80)
    p.drawPixmap(size_w // 2 - 40, 30, logo)

    # Title
    p.setPen(QColor("#00d4ff"))
    f = QFont("Consolas", 24, QFont.Bold)
    p.setFont(f)
    p.drawText(QRect(0, 125, size_w, 50), Qt.AlignCenter, "⚡ NETSCAN")

    # Subtitle
    p.setPen(QColor("#6e7681"))
    f2 = QFont("Consolas", 9)
    p.setFont(f2)
    p.drawText(
        QRect(0, 168, size_w, 30),
        Qt.AlignCenter,
        "ADVANCED NETWORK SECURITY MONITOR",
    )

    # Version
    p.setPen(QColor("#3fb950"))
    f3 = QFont("Consolas", 9)
    p.setFont(f3)
    p.drawText(QRect(0, 200, size_w, 24), Qt.AlignCenter, "v2.0.0")

    # Author
    p.setPen(QColor("#6e7681"))
    f4 = QFont("Consolas", 8)
    p.setFont(f4)
    p.drawText(
        QRect(0, size_h - 30, size_w, 24),
        Qt.AlignCenter,
        "by Mohamed Ahmed  —  running on Linux/Windows/macOS",
    )

    # Scan line animation effect (static)
    pen3 = QPen(QColor(0, 212, 255, 30), 1)
    p.setPen(pen3)
    for y in range(0, size_h, 6):
        p.drawLine(0, y, size_w, y)

    p.end()
    return pix


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("NetScan")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("Mohamed Ahmed")

    # Splash
    splash_pix = create_splash()
    splash = QSplashScreen(splash_pix, Qt.WindowStaysOnTopHint)
    splash.show()
    app.processEvents()

    # Build main window (heavy init happens here)
    window = MainWindow()
    icon_pix = create_app_icon(256)
    window.setWindowIcon(QIcon(icon_pix))

    def show_main():
        splash.close()
        window.show()

    QTimer.singleShot(1800, show_main)
    raise SystemExit(app.exec())


if __name__ == "__main__":
    main()

