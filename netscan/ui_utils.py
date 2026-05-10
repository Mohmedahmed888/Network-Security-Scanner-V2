"""
UI Helper Functions
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableWidgetItem
from PySide6.QtGui import QFont


def item(text: str, center: bool = False) -> QTableWidgetItem:
    """Create a non-editable table item"""
    it = QTableWidgetItem(text)
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    if center:
        it.setTextAlignment(Qt.AlignCenter)
    return it


def icon_for_device_type(device_type: str) -> str:
    """Return emoji icon for device type"""
    t = (device_type or "").lower()
    
    if "router" in t or "gateway" in t:
        return "🌐"
    if "laptop" in t:
        return "💻"
    if "computer" in t or "pc" in t or "desktop" in t:
        return "🖥️"
    if "mobile" in t or "iphone" in t or "android" in t:
        return "📱"
    if "tv" in t:
        return "📺"
    if "printer" in t:
        return "🖨️"
    
    return "❓"


