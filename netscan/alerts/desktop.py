from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QSystemTrayIcon


class DesktopNotifier(QObject):
    def __init__(self, parent=None, icon: Optional[QIcon] = None):
        super().__init__(parent)
        self.tray = QSystemTrayIcon(parent)
        if icon is not None:
            self.tray.setIcon(icon)
        self.tray.setVisible(True)

    def notify(self, title: str, message: str, msecs: int = 8000):
        if not self.tray.isVisible():
            self.tray.setVisible(True)
        self.tray.showMessage(title, message, QSystemTrayIcon.Information, msecs)

