"""
Create Desktop Shortcut for Network Security Scanner
"""

import os
import sys
from pathlib import Path

try:
    import win32com.client
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


def create_shortcut():
    """Create desktop shortcut"""
    desktop = Path.home() / "Desktop"
    exe_path = Path(__file__).parent / "dist" / "NetworkSecurityScanner.exe"
    
    if not exe_path.exists():
        # If exe doesn't exist, use python script
        exe_path = Path(__file__).parent / "main.py"
        target = f'pythonw.exe "{exe_path}"'
        icon_path = exe_path
    else:
        target = str(exe_path)
        icon_path = target
    
    shortcut_path = desktop / "Network Security Scanner.lnk"
    
    if HAS_WIN32:
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(str(shortcut_path))
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = str(Path(__file__).parent)
        shortcut.IconLocation = str(icon_path)
        shortcut.Description = "Network Security Scanner - Advanced Network Monitor"
        shortcut.save()
        print(f"Shortcut created at: {shortcut_path}")
    else:
        # Create .bat file as alternative
        bat_content = f'@echo off\ncd /d "{Path(__file__).parent}"\n"{sys.executable}" "{exe_path}"\npause'
        bat_path = desktop / "Network Security Scanner.bat"
        bat_path.write_text(bat_content)
        print(f"Batch file created at: {bat_path}")
        print("Note: Install pywin32 for .lnk shortcut: pip install pywin32")


if __name__ == "__main__":
    create_shortcut()


