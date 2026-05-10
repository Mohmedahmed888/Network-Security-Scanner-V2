# Linux Installation & Usage Guide

## Prerequisites

### System Requirements
- Linux distribution (Ubuntu, Debian, Fedora, Arch, etc.)
- Python 3.8 or higher
- Network tools (ping, arp, ip)

### Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install python3 python3-pip iputils-ping net-tools iproute2
```

**Fedora/RHEL:**
```bash
sudo dnf install python3 python3-pip iputils net-tools iproute
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip iputils net-tools iproute2
```

## Installation

### Quick Setup
```bash
chmod +x setup_linux.sh
./setup_linux.sh
```

### Manual Setup
```bash
pip3 install -r requirements.txt
```

## Running the Application

```bash
python3 main.py
```

Or (recommended):

```bash
python3 -m netscan
```

## Building Executable (Linux)

You can also build a standalone executable using PyInstaller:

```bash
pip3 install pyinstaller
pyinstaller --name="NetworkSecurityScanner" --onefile --windowed main.py
```

The executable will be in the `dist/` folder.

## Troubleshooting

### Permission Denied for ping
If you get permission errors:
```bash
sudo chmod +s /bin/ping
```

Or run with sudo (not recommended for security):
```bash
sudo python3 main.py
```

### ARP table access
The application needs access to ARP table. If it doesn't work:
- Ensure you have proper network permissions
- Check if `arp` command is available: `which arp`

### Missing network tools
Install missing tools based on your distribution (see Prerequisites above).

## Notes

- The application works the same way on Linux as on Windows
- All features are cross-platform compatible
- GUI requires X11 or Wayland display server

