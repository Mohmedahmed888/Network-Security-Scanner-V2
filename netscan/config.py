"""
Configuration and Data
Ports, Vulnerabilities, Trusted IPs, MAC OUI Database
"""

import subprocess
import re
import platform
from typing import List, Optional

# ─────────────────────────────────────────────────
# Ports & Services
# ─────────────────────────────────────────────────
COMMON_PORTS = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP (Mail)",
    53:    "DNS",
    80:    "HTTP (Web)",
    110:   "POP3 (Mail)",
    139:   "NetBIOS",
    143:   "IMAP (Mail)",
    443:   "HTTPS (Secure Web)",
    445:   "SMB (File Sharing)",
    1883:  "MQTT (IoT)",
    3306:  "MySQL",
    3389:  "RDP (Remote Desktop)",
    5900:  "VNC (Remote Desktop)",
    6443:  "Kubernetes API",
    8080:  "HTTP Alt / Proxy",
    8443:  "HTTPS Alt",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}

SECURITY_ADVICE = {
    21:    "FTP is unencrypted. Use SFTP/FTPS or close this port if not needed.",
    22:    "SSH is sensitive. Use strong passwords or keys and limit access.",
    23:    "Telnet is very insecure (no encryption). Disable and use SSH instead.",
    25:    "Mail server port. Make sure it's properly configured and not open to relay spam.",
    80:    "HTTP is not encrypted. Prefer HTTPS (443) for sensitive data.",
    139:   "NetBIOS file sharing. Close if file sharing is not required.",
    445:   "SMB file sharing. Vulnerable in many attacks (e.g., WannaCry). Restrict or close.",
    1883:  "MQTT broker. Ensure authentication is enabled. Never expose to internet.",
    3306:  "MySQL database. Never expose to the Internet. Restrict access to local hosts.",
    3389:  "RDP remote desktop. High-risk. Use VPN and strong authentication only.",
    5900:  "VNC remote desktop. Use strong passwords and restrict access.",
    8080:  "HTTP alternate port. May expose admin panels or proxies.",
    9200:  "Elasticsearch should NEVER be exposed publicly — no auth by default.",
    27017: "MongoDB: Ensure authentication is enabled. Never expose to internet.",
}

# ─────────────────────────────────────────────────
# Vulnerability Database
# ─────────────────────────────────────────────────
VULNERABILITIES = {
    21: [
        {
            "name": "FTP Anonymous Login",
            "severity": "Medium", "strength": "Weak",
            "description": "FTP server may allow anonymous login without authentication",
            "impact": "Unauthorized users can access FTP server and potentially upload/download files",
            "recommendation": "Disable anonymous login and require strong authentication"
        },
        {
            "name": "FTP Unencrypted Data",
            "severity": "High", "strength": "Weak",
            "description": "FTP transmits all data including passwords in plaintext over the network",
            "impact": "Sensitive data and credentials can be intercepted by attackers",
            "recommendation": "Use SFTP or FTPS instead of plain FTP"
        }
    ],
    22: [
        {
            "name": "SSH Weak Algorithms",
            "severity": "Medium", "strength": "Weak",
            "description": "SSH may use weak encryption algorithms or outdated protocols",
            "impact": "Encrypted connections may be compromised by attackers",
            "recommendation": "Configure SSH to use strong encryption algorithms only"
        },
        {
            "name": "SSH Brute Force Risk",
            "severity": "High", "strength": "Strong",
            "description": "SSH service exposed to brute force attacks due to default configuration",
            "impact": "Attackers can attempt to guess passwords and gain unauthorized access",
            "recommendation": "Implement fail2ban, use key-based authentication, and change default port"
        }
    ],
    23: [
        {
            "name": "Telnet Unencrypted",
            "severity": "Critical", "strength": "Very Weak",
            "description": "Telnet transmits all data including passwords completely unencrypted",
            "impact": "All traffic can be intercepted and credentials stolen by anyone on the network",
            "recommendation": "Immediately disable Telnet and use SSH instead"
        }
    ],
    80: [
        {
            "name": "HTTP Unencrypted",
            "severity": "High", "strength": "Weak",
            "description": "HTTP transmits all data without encryption over the network",
            "impact": "Sensitive information, session cookies, and user credentials can be intercepted",
            "recommendation": "Redirect HTTP to HTTPS and use SSL/TLS encryption"
        },
        {
            "name": "Web Server Vulnerabilities",
            "severity": "Medium", "strength": "Medium",
            "description": "Web server may have known vulnerabilities in installed version",
            "impact": "Attackers can exploit vulnerabilities to gain access or perform attacks",
            "recommendation": "Keep web server software updated to latest version"
        }
    ],
    443: [
        {
            "name": "SSL/TLS Weak Ciphers",
            "severity": "Medium", "strength": "Weak",
            "description": "HTTPS may use weak SSL/TLS ciphers or outdated protocols",
            "impact": "Encrypted connections may be broken using known cryptographic weaknesses",
            "recommendation": "Disable weak ciphers and use only strong TLS 1.2+ protocols"
        },
        {
            "name": "Certificate Issues",
            "severity": "Low", "strength": "Weak",
            "description": "SSL certificate may be expired, self-signed, or invalid",
            "impact": "Users may see security warnings or connections may be less secure",
            "recommendation": "Use valid SSL certificates from trusted certificate authority"
        }
    ],
    445: [
        {
            "name": "SMB EternalBlue",
            "severity": "Critical", "strength": "Very Strong",
            "description": "SMB vulnerable to EternalBlue exploit used by WannaCry ransomware",
            "impact": "Remote code execution possible, allowing complete system compromise",
            "recommendation": "Immediately apply MS17-010 patch or disable SMBv1 protocol"
        },
        {
            "name": "SMB Unauthenticated Access",
            "severity": "High", "strength": "Strong",
            "description": "SMB file sharing may allow unauthenticated guest access",
            "impact": "Unauthorized users can access shared files and folders",
            "recommendation": "Require authentication for SMB shares and disable guest access"
        }
    ],
    1883: [
        {
            "name": "MQTT No Authentication",
            "severity": "High", "strength": "Weak",
            "description": "MQTT broker may accept connections without authentication",
            "impact": "Attackers can subscribe to all topics and intercept IoT device data",
            "recommendation": "Enable username/password authentication and TLS encryption on MQTT"
        }
    ],
    3389: [
        {
            "name": "RDP BlueKeep",
            "severity": "Critical", "strength": "Very Strong",
            "description": "RDP vulnerable to BlueKeep (CVE-2019-0708) remote code execution exploit",
            "impact": "Remote attackers can execute code without authentication, leading to full system control",
            "recommendation": "Apply security patch KB4499175 immediately or disable RDP if not needed"
        },
        {
            "name": "RDP Brute Force",
            "severity": "High", "strength": "Strong",
            "description": "RDP service exposed to brute force attacks on default port",
            "impact": "Attackers can attempt to guess passwords and gain remote desktop access",
            "recommendation": "Use strong passwords, enable NLA, change default port, use VPN"
        },
        {
            "name": "RDP Weak Encryption",
            "severity": "Medium", "strength": "Weak",
            "description": "RDP may use weak encryption algorithms",
            "impact": "Remote desktop sessions may be less secure",
            "recommendation": "Configure RDP to use high-level encryption (FIPS 140-1 validated)"
        }
    ],
    3306: [
        {
            "name": "MySQL Weak Authentication",
            "severity": "High", "strength": "Medium",
            "description": "MySQL database may have weak authentication or default credentials",
            "impact": "Unauthorized access to database containing sensitive information",
            "recommendation": "Use strong passwords, create specific database users with minimal privileges"
        },
        {
            "name": "MySQL Remote Access",
            "severity": "Critical", "strength": "Strong",
            "description": "MySQL database exposed to network access",
            "impact": "Database accessible from internet, vulnerable to attacks and data theft",
            "recommendation": "Restrict MySQL access to localhost only, use firewall rules"
        }
    ],
    5900: [
        {
            "name": "VNC No Authentication",
            "severity": "Critical", "strength": "Very Weak",
            "description": "VNC may be running without password protection",
            "impact": "Anyone on the network can take full control of the desktop",
            "recommendation": "Set a strong VNC password and restrict access with firewall rules"
        }
    ],
    9200: [
        {
            "name": "Elasticsearch Open Access",
            "severity": "Critical", "strength": "Very Weak",
            "description": "Elasticsearch exposes all data without authentication by default",
            "impact": "Entire database exposed — data theft, modification, or deletion possible",
            "recommendation": "Enable X-Pack security, set passwords, bind to localhost only"
        }
    ],
    27017: [
        {
            "name": "MongoDB No Auth",
            "severity": "Critical", "strength": "Very Weak",
            "description": "MongoDB may be running without authentication enabled",
            "impact": "All databases fully exposed — billions of records breached this way historically",
            "recommendation": "Enable authentication, bind to localhost, use firewall rules"
        }
    ]
}

# ─────────────────────────────────────────────────
# MAC OUI Database (Vendor Detection)
# ─────────────────────────────────────────────────
OUI_DATABASE = {
    # Apple
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0a:27": "Apple",
    "00:0a:95": "Apple", "00:11:24": "Apple", "00:14:51": "Apple",
    "00:16:cb": "Apple", "00:17:f2": "Apple", "00:19:e3": "Apple",
    "00:1b:63": "Apple", "00:1c:b3": "Apple", "00:1d:4f": "Apple",
    "00:1e:52": "Apple", "00:1e:c2": "Apple", "00:1f:5b": "Apple",
    "00:1f:f3": "Apple", "00:21:e9": "Apple", "00:22:41": "Apple",
    "00:23:12": "Apple", "00:23:32": "Apple", "00:23:6c": "Apple",
    "00:23:df": "Apple", "00:24:36": "Apple", "00:25:00": "Apple",
    "00:25:4b": "Apple", "00:25:bc": "Apple", "00:26:08": "Apple",
    "00:26:4a": "Apple", "00:26:b9": "Apple", "00:26:bb": "Apple",
    "00:30:65": "Apple", "04:0c:ce": "Apple", "04:15:52": "Apple",
    "04:1e:64": "Apple", "04:26:65": "Apple", "04:4b:ed": "Apple",
    "04:54:53": "Apple", "04:d3:cf": "Apple", "04:e5:36": "Apple",
    "08:6d:41": "Apple", "08:70:45": "Apple", "0c:3e:9f": "Apple",
    "0c:4d:e9": "Apple", "0c:74:c2": "Apple", "10:1c:0c": "Apple",
    "10:40:f3": "Apple", "10:9a:dd": "Apple", "14:99:e2": "Apple",
    "14:bd:61": "Apple", "18:20:32": "Apple", "18:34:51": "Apple",
    "18:65:90": "Apple", "18:e7:f4": "Apple", "1c:1a:c0": "Apple",
    "1c:36:bb": "Apple", "20:78:f0": "Apple", "20:c9:d0": "Apple",
    "24:a0:74": "Apple", "24:ab:81": "Apple", "28:37:37": "Apple",
    "28:6a:b8": "Apple", "2c:be:08": "Apple", "2c:f0:a2": "Apple",
    "34:15:9e": "Apple", "34:51:c9": "Apple", "38:0f:4a": "Apple",
    "38:48:4c": "Apple", "3c:07:54": "Apple", "3c:15:c2": "Apple",
    "40:30:04": "Apple", "40:6c:8f": "Apple", "40:83:1d": "Apple",
    "40:a6:d9": "Apple", "44:4c:0c": "Apple", "44:d8:84": "Apple",
    "48:43:7c": "Apple", "48:60:bc": "Apple", "4c:57:ca": "Apple",
    "4c:74:bf": "Apple", "50:7a:55": "Apple", "54:72:4f": "Apple",
    "54:ae:27": "Apple", "58:1f:aa": "Apple", "58:55:ca": "Apple",
    "5c:95:ae": "Apple", "5c:f7:e6": "Apple", "60:03:08": "Apple",
    "60:33:4b": "Apple", "60:f4:45": "Apple", "60:fb:42": "Apple",
    "64:20:0c": "Apple", "64:76:ba": "Apple", "64:9a:be": "Apple",
    "68:5b:35": "Apple", "68:64:4b": "Apple", "68:9c:70": "Apple",
    "6c:40:08": "Apple", "6c:72:e7": "Apple", "6c:ab:31": "Apple",
    "70:11:24": "Apple", "70:56:81": "Apple", "70:73:cb": "Apple",
    "70:81:eb": "Apple", "74:81:14": "Apple", "74:e2:f5": "Apple",
    "78:31:c1": "Apple", "78:4f:43": "Apple", "7c:11:be": "Apple",
    "7c:6d:62": "Apple", "7c:d1:c3": "Apple", "80:e6:50": "Apple",
    "84:38:35": "Apple", "84:78:8b": "Apple", "84:85:06": "Apple",
    "84:b1:53": "Apple", "88:19:08": "Apple", "88:53:95": "Apple",
    "88:66:a5": "Apple", "88:e8:7f": "Apple", "8c:00:6d": "Apple",
    "8c:7c:92": "Apple", "90:72:40": "Apple", "90:fd:61": "Apple",
    "94:bf:2d": "Apple", "98:01:a7": "Apple", "98:10:e7": "Apple",
    "98:d6:bb": "Apple", "9c:04:eb": "Apple", "9c:20:7b": "Apple",
    "a4:5e:60": "Apple", "a4:c3:61": "Apple", "a4:d1:8c": "Apple",
    "a8:20:66": "Apple", "a8:5c:2c": "Apple", "a8:86:dd": "Apple",
    "a8:96:8a": "Apple", "ac:07:5f": "Apple", "ac:29:3a": "Apple",
    "ac:3c:0b": "Apple", "ac:61:ea": "Apple", "ac:87:a3": "Apple",
    "ac:bc:32": "Apple", "ac:cf:5c": "Apple", "b0:34:95": "Apple",
    "b4:18:d1": "Apple", "b4:4b:d2": "Apple", "b4:f0:ab": "Apple",
    "b8:09:8a": "Apple", "b8:17:c2": "Apple", "b8:5d:0a": "Apple",
    "b8:78:2e": "Apple", "b8:8d:12": "Apple", "bc:3b:af": "Apple",
    "bc:52:b7": "Apple", "bc:a9:20": "Apple", "c0:84:7a": "Apple",
    "c4:2c:03": "Apple", "c4:b3:01": "Apple", "c8:33:4b": "Apple",
    "c8:69:cd": "Apple", "c8:b5:b7": "Apple", "c8:d0:83": "Apple",
    "cc:08:8d": "Apple", "cc:20:e8": "Apple", "cc:29:f5": "Apple",
    "d0:23:db": "Apple", "d0:a6:37": "Apple", "d4:90:9c": "Apple",
    "d4:f4:6f": "Apple", "d8:00:4d": "Apple", "d8:1d:72": "Apple",
    "d8:30:62": "Apple", "d8:96:95": "Apple", "d8:bb:2c": "Apple",
    "dc:2b:2a": "Apple", "dc:37:14": "Apple", "dc:9b:9c": "Apple",
    "e0:ac:cb": "Apple", "e0:f5:c6": "Apple", "e4:25:e7": "Apple",
    "e4:8b:7f": "Apple", "e4:9a:79": "Apple", "e4:c6:3d": "Apple",
    "e8:06:88": "Apple", "e8:04:0b": "Apple", "ec:35:86": "Apple",
    "f0:18:98": "Apple", "f0:d1:a9": "Apple", "f4:1b:a1": "Apple",
    "f4:31:c3": "Apple", "f4:37:b7": "Apple", "f8:1e:df": "Apple",
    "f8:27:93": "Apple", "f8:62:14": "Apple", "fc:25:3f": "Apple",
    "fc:e9:98": "Apple",
    # Samsung
    "00:00:f0": "Samsung", "00:02:78": "Samsung", "00:07:ab": "Samsung",
    "00:12:47": "Samsung", "00:13:77": "Samsung", "00:15:b9": "Samsung",
    "00:16:32": "Samsung", "00:17:c9": "Samsung", "00:18:af": "Samsung",
    "00:1a:8a": "Samsung", "00:1b:98": "Samsung", "00:1c:43": "Samsung",
    "00:1d:25": "Samsung", "00:1e:7d": "Samsung", "00:1f:cc": "Samsung",
    "00:21:19": "Samsung", "00:23:39": "Samsung", "00:25:67": "Samsung",
    "04:18:d6": "Samsung", "04:32:f4": "Samsung", "04:f1:7e": "Samsung",
    "08:08:c2": "Samsung", "0c:89:10": "Samsung", "10:1d:c0": "Samsung",
    "14:49:e0": "Samsung", "18:1e:b0": "Samsung", "1c:af:05": "Samsung",
    "20:13:e0": "Samsung", "24:4b:81": "Samsung", "2c:57:31": "Samsung",
    "30:07:4d": "Samsung", "34:c3:d2": "Samsung", "38:0a:94": "Samsung",
    "40:0e:85": "Samsung", "44:78:3e": "Samsung", "48:44:f7": "Samsung",
    "4c:3c:16": "Samsung", "50:01:bb": "Samsung", "50:32:37": "Samsung",
    "54:88:0e": "Samsung", "58:ef:68": "Samsung", "5c:35:3b": "Samsung",
    "60:6b:bd": "Samsung", "64:1c:ae": "Samsung", "68:eb:ae": "Samsung",
    "6c:2f:2c": "Samsung", "74:45:8a": "Samsung", "78:40:e4": "Samsung",
    "7c:11:cf": "Samsung", "80:57:19": "Samsung", "84:38:38": "Samsung",
    "88:32:9b": "Samsung", "8c:71:f8": "Samsung", "90:18:7c": "Samsung",
    "94:51:03": "Samsung", "98:52:b1": "Samsung", "9c:02:98": "Samsung",
    "a0:07:98": "Samsung", "a0:0b:ba": "Samsung", "a4:eb:d3": "Samsung",
    "a8:7d:12": "Samsung", "ac:36:13": "Samsung", "b0:47:bf": "Samsung",
    "b4:07:f9": "Samsung", "b8:bc:1b": "Samsung", "bc:14:ef": "Samsung",
    "c0:bd:d1": "Samsung", "c4:57:6e": "Samsung", "c8:ba:94": "Samsung",
    "cc:05:1b": "Samsung", "d0:17:6a": "Samsung", "d0:22:be": "Samsung",
    "d4:87:d8": "Samsung", "d8:57:ef": "Samsung", "dc:71:96": "Samsung",
    "e0:99:71": "Samsung", "e4:32:cb": "Samsung", "e8:9f:80": "Samsung",
    "ec:9b:f3": "Samsung", "f0:5b:7b": "Samsung", "f0:72:ea": "Samsung",
    "f4:42:8f": "Samsung", "f8:04:2e": "Samsung", "fc:a6:21": "Samsung",
    # Xiaomi
    "00:9e:c8": "Xiaomi", "04:cf:8c": "Xiaomi", "0c:1d:af": "Xiaomi",
    "10:2a:b3": "Xiaomi", "14:f6:5a": "Xiaomi", "18:59:36": "Xiaomi",
    "20:82:c0": "Xiaomi", "28:6c:07": "Xiaomi", "2c:4d:54": "Xiaomi",
    "34:80:b3": "Xiaomi", "38:a4:ed": "Xiaomi", "3c:bd:3e": "Xiaomi",
    "4c:63:71": "Xiaomi", "50:8f:4c": "Xiaomi", "58:44:98": "Xiaomi",
    "64:09:80": "Xiaomi", "68:df:dd": "Xiaomi", "6c:5a:b0": "Xiaomi",
    "74:51:ba": "Xiaomi", "78:11:dc": "Xiaomi", "7c:1d:d9": "Xiaomi",
    "8c:be:be": "Xiaomi", "94:fb:29": "Xiaomi", "a4:50:46": "Xiaomi",
    "ac:f7:f3": "Xiaomi", "b0:e2:35": "Xiaomi", "b4:0b:44": "Xiaomi",
    "bc:99:11": "Xiaomi", "c4:6a:b7": "Xiaomi", "c8:14:79": "Xiaomi",
    "d4:97:0b": "Xiaomi", "f4:8b:32": "Xiaomi", "f8:a4:5f": "Xiaomi",
    "fc:64:ba": "Xiaomi",
    # Huawei
    "00:18:82": "Huawei", "00:1e:10": "Huawei", "00:25:9e": "Huawei",
    "04:02:1f": "Huawei", "04:b0:e7": "Huawei", "04:c0:6f": "Huawei",
    "04:f9:38": "Huawei", "08:00:0f": "Huawei", "0c:37:dc": "Huawei",
    "0c:96:bf": "Huawei", "10:1b:54": "Huawei", "10:47:80": "Huawei",
    "14:a5:1a": "Huawei", "18:c5:8a": "Huawei", "1c:8e:5c": "Huawei",
    "20:08:ed": "Huawei", "24:4c:07": "Huawei", "28:31:52": "Huawei",
    "2c:ab:00": "Huawei", "30:87:d9": "Huawei", "34:00:a3": "Huawei",
    "38:f8:89": "Huawei", "3c:df:bd": "Huawei", "40:4d:8e": "Huawei",
    "44:55:b1": "Huawei", "48:00:31": "Huawei", "4c:1f:cc": "Huawei",
    "50:68:0a": "Huawei", "54:89:98": "Huawei", "58:25:75": "Huawei",
    "5c:c3:07": "Huawei", "60:de:44": "Huawei", "64:3e:8c": "Huawei",
    "68:a0:f6": "Huawei", "6c:8d:c1": "Huawei", "70:7b:e8": "Huawei",
    "74:a0:63": "Huawei", "78:1d:ba": "Huawei", "7c:60:97": "Huawei",
    "80:71:1f": "Huawei", "84:ad:58": "Huawei", "88:a2:5e": "Huawei",
    "8c:0d:76": "Huawei", "90:17:3f": "Huawei", "94:04:9c": "Huawei",
    "98:e7:f4": "Huawei", "9c:28:ef": "Huawei", "a4:ca:a0": "Huawei",
    "a8:ca:7b": "Huawei", "ac:e2:15": "Huawei", "b8:08:d7": "Huawei",
    "bc:25:e0": "Huawei", "c0:70:09": "Huawei", "c4:07:2f": "Huawei",
    "c8:51:95": "Huawei", "cc:96:a0": "Huawei", "d0:7a:b5": "Huawei",
    "d4:6e:5c": "Huawei", "d8:c7:71": "Huawei", "dc:d2:fc": "Huawei",
    "e0:19:1d": "Huawei", "e4:68:a3": "Huawei", "e8:cd:2d": "Huawei",
    "ec:23:3d": "Huawei", "f0:79:59": "Huawei", "f4:55:9c": "Huawei",
    "f8:01:13": "Huawei", "fc:48:ef": "Huawei",
    # Cisco
    "00:00:0c": "Cisco", "00:01:42": "Cisco", "00:01:63": "Cisco",
    "00:01:64": "Cisco", "00:01:96": "Cisco", "00:01:97": "Cisco",
    "00:02:16": "Cisco", "00:02:17": "Cisco", "00:03:31": "Cisco",
    "00:03:6b": "Cisco", "00:04:4d": "Cisco", "00:06:28": "Cisco",
    "00:07:0d": "Cisco", "00:07:50": "Cisco", "00:07:84": "Cisco",
    "00:07:eb": "Cisco", "00:08:20": "Cisco", "00:0a:41": "Cisco",
    "00:0b:45": "Cisco", "00:0b:be": "Cisco", "00:0c:30": "Cisco",
    "00:0c:85": "Cisco", "00:0d:28": "Cisco", "00:0d:bc": "Cisco",
    "00:0e:08": "Cisco", "00:0e:38": "Cisco", "00:0e:84": "Cisco",
    "00:0e:d7": "Cisco", "00:0f:23": "Cisco", "00:0f:66": "Cisco",
    "00:0f:8f": "Cisco", "00:0f:f7": "Cisco", "00:10:07": "Cisco",
    "00:10:11": "Cisco", "00:10:14": "Cisco", "00:17:df": "Cisco",
    "00:19:06": "Cisco", "00:1a:2f": "Cisco", "00:1a:a1": "Cisco",
    "00:1b:2b": "Cisco", "00:1b:8f": "Cisco", "00:1c:0e": "Cisco",
    "00:1d:45": "Cisco", "00:1d:70": "Cisco", "00:1e:13": "Cisco",
    "00:1e:49": "Cisco", "00:1e:be": "Cisco", "00:1f:26": "Cisco",
    "00:1f:9e": "Cisco", "00:21:1b": "Cisco", "00:21:55": "Cisco",
    "00:22:0c": "Cisco", "00:22:55": "Cisco", "00:22:90": "Cisco",
    "00:22:bd": "Cisco", "00:23:04": "Cisco", "00:23:ac": "Cisco",
    "00:24:13": "Cisco", "00:24:97": "Cisco", "00:24:c4": "Cisco",
    "00:25:45": "Cisco", "00:25:84": "Cisco", "00:25:b4": "Cisco",
    "00:26:0a": "Cisco", "00:26:51": "Cisco", "00:26:99": "Cisco",
    "00:26:ca": "Cisco", "00:27:0d": "Cisco", "00:30:19": "Cisco",
    "00:30:24": "Cisco", "00:30:48": "Cisco", "00:30:78": "Cisco",
    "00:30:80": "Cisco", "00:30:96": "Cisco", "00:30:a3": "Cisco",
    "00:30:f2": "Cisco", "00:40:96": "Cisco", "00:50:0f": "Cisco",
    "00:50:50": "Cisco", "00:60:2f": "Cisco", "00:60:3e": "Cisco",
    "00:60:47": "Cisco", "00:60:5c": "Cisco", "00:60:70": "Cisco",
    "00:60:83": "Cisco", "00:60:97": "Cisco", "00:60:b0": "Cisco",
    "00:e0:14": "Cisco", "00:e0:1e": "Cisco", "00:e0:4f": "Cisco",
    "00:e0:a3": "Cisco", "00:e0:b0": "Cisco", "00:e0:f7": "Cisco",
    # TP-Link
    "00:27:19": "TP-Link", "10:fe:ed": "TP-Link", "14:cc:20": "TP-Link",
    "18:a6:f7": "TP-Link", "1c:3b:f3": "TP-Link", "20:dc:e6": "TP-Link",
    "24:69:a5": "TP-Link", "28:28:5d": "TP-Link", "2c:f0:5d": "TP-Link",
    "30:b5:c2": "TP-Link", "34:ea:34": "TP-Link", "38:6b:bb": "TP-Link",
    "3c:46:d8": "TP-Link", "40:16:9f": "TP-Link", "44:94:fc": "TP-Link",
    "48:8d:36": "TP-Link", "4c:5e:0c": "TP-Link", "50:3e:aa": "TP-Link",
    "54:af:97": "TP-Link", "58:d5:6e": "TP-Link", "5c:89:9a": "TP-Link",
    "60:e3:27": "TP-Link", "64:70:02": "TP-Link", "68:ff:7b": "TP-Link",
    "6c:19:8f": "TP-Link", "70:4f:57": "TP-Link", "74:ea:3a": "TP-Link",
    "78:8a:20": "TP-Link", "7c:39:53": "TP-Link", "80:35:c1": "TP-Link",
    "84:16:f9": "TP-Link", "88:25:93": "TP-Link", "8c:21:0a": "TP-Link",
    "90:f6:52": "TP-Link", "94:d9:b3": "TP-Link", "98:da:c4": "TP-Link",
    "9c:5c:8e": "TP-Link", "a0:f3:c1": "TP-Link", "a4:2b:b0": "TP-Link",
    "a8:57:4e": "TP-Link", "ac:84:c6": "TP-Link", "b0:48:7a": "TP-Link",
    "b4:b0:24": "TP-Link", "b8:f8:83": "TP-Link", "bc:46:99": "TP-Link",
    "c0:06:c3": "TP-Link", "c4:e9:84": "TP-Link", "c8:0e:14": "TP-Link",
    "cc:32:e5": "TP-Link", "d0:37:45": "TP-Link", "d4:6e:0e": "TP-Link",
    "d8:0d:17": "TP-Link", "dc:fe:18": "TP-Link", "e0:05:c5": "TP-Link",
    "e4:f7:5b": "TP-Link", "e8:de:27": "TP-Link", "ec:08:6b": "TP-Link",
    "f0:a7:31": "TP-Link", "f4:ec:38": "TP-Link", "f8:1a:67": "TP-Link",
    "fc:7c:02": "TP-Link",
    # Netgear
    "00:04:e2": "Netgear", "00:09:5b": "Netgear", "00:0f:b5": "Netgear",
    "00:14:6c": "Netgear", "00:18:4d": "Netgear", "00:1b:2f": "Netgear",
    "00:1e:2a": "Netgear", "00:1f:33": "Netgear", "00:22:3f": "Netgear",
    "00:24:b2": "Netgear", "00:26:f2": "Netgear", "04:a1:51": "Netgear",
    "08:02:8e": "Netgear", "08:36:c9": "Netgear", "0c:3d:c9": "Netgear",
    "10:0c:6b": "Netgear", "10:da:43": "Netgear", "14:59:c0": "Netgear",
    "20:0c:c8": "Netgear", "20:4e:7f": "Netgear", "28:c6:8e": "Netgear",
    "2c:b0:5d": "Netgear", "30:46:9a": "Netgear", "4c:60:de": "Netgear",
    "6c:b0:ce": "Netgear", "74:44:01": "Netgear", "84:1b:5e": "Netgear",
    "9c:3d:cf": "Netgear", "a0:04:60": "Netgear", "a0:21:b7": "Netgear",
    "a4:2b:8c": "Netgear", "b0:39:56": "Netgear", "c0:3f:0e": "Netgear",
    "c4:3d:c7": "Netgear", "e0:91:f5": "Netgear", "e4:f4:c6": "Netgear",
    # Intel (laptops/PCs)
    "00:02:b3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel",
    "00:07:e9": "Intel", "00:0c:e7": "Intel", "00:0c:f1": "Intel",
    "00:0d:56": "Intel", "00:0e:0c": "Intel", "00:0e:35": "Intel",
    "00:11:11": "Intel", "00:12:f0": "Intel", "00:13:02": "Intel",
    "00:13:20": "Intel", "00:13:e8": "Intel", "00:15:00": "Intel",
    "00:15:17": "Intel", "00:16:6f": "Intel", "00:16:76": "Intel",
    "00:16:ea": "Intel", "00:17:08": "Intel", "00:18:de": "Intel",
    "00:19:d1": "Intel", "00:1b:21": "Intel", "00:1c:bf": "Intel",
    "00:1d:e0": "Intel", "00:1e:64": "Intel", "00:1f:3b": "Intel",
    "00:21:6a": "Intel", "00:22:fa": "Intel", "00:23:14": "Intel",
    "00:24:d6": "Intel", "00:25:d3": "Intel", "00:26:c6": "Intel",
    "00:27:10": "Intel",
    # Realtek
    "00:01:2e": "Realtek", "00:01:6c": "Realtek", "00:e0:4c": "Realtek",
    "00:e0:7d": "Realtek", "52:54:00": "VirtualBox/QEMU",
    # Raspberry Pi
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "28:cd:c1": "Raspberry Pi",
    # Amazon (Echo, Fire TV)
    "00:fc:8b": "Amazon", "10:ae:60": "Amazon", "18:74:2e": "Amazon",
    "28:ef:01": "Amazon", "34:d2:70": "Amazon", "38:f7:3d": "Amazon",
    "40:b4:cd": "Amazon", "44:65:0d": "Amazon", "48:23:35": "Amazon",
    "4c:ef:c0": "Amazon", "50:f5:da": "Amazon", "54:44:08": "Amazon",
    "68:37:e9": "Amazon", "74:75:48": "Amazon", "78:e1:03": "Amazon",
    "84:d6:d0": "Amazon", "88:71:e5": "Amazon", "8c:85:80": "Amazon",
    "a4:08:01": "Amazon", "ac:63:be": "Amazon", "b4:7c:9c": "Amazon",
    "b8:81:fa": "Amazon", "c4:a3:66": "Amazon", "e8:b2:ac": "Amazon",
    "f0:27:2d": "Amazon", "f0:d2:f1": "Amazon", "fc:65:de": "Amazon",
    # Google (Nest, Chromecast, Pixel)
    "00:1a:11": "Google", "00:4e:01": "Google", "08:9e:08": "Google",
    "1c:f2:9a": "Google", "20:df:b9": "Google", "28:f0:76": "Google",
    "3c:5a:b4": "Google", "48:d6:d5": "Google", "54:60:09": "Google",
    "78:58:60": "Google", "84:10:0d": "Google", "8c:85:90": "Google",
    "90:b0:ed": "Google", "94:eb:2c": "Google", "a4:77:33": "Google",
    "ac:37:43": "Google", "b8:81:98": "Google", "d8:6c:63": "Google",
    "e4:f0:42": "Google", "f4:f5:d8": "Google",
    # Dell
    "00:06:5b": "Dell", "00:08:74": "Dell", "00:0b:db": "Dell",
    "00:0d:56": "Dell", "00:0f:1f": "Dell", "00:11:43": "Dell",
    "00:12:3f": "Dell", "00:13:72": "Dell", "00:14:22": "Dell",
    "00:15:c5": "Dell", "00:16:f0": "Dell", "00:18:8b": "Dell",
    "00:19:b9": "Dell", "00:1a:4b": "Dell", "00:1c:23": "Dell",
    "00:1d:09": "Dell", "00:1e:4f": "Dell", "00:1f:d0": "Dell",
    "00:21:70": "Dell", "00:22:19": "Dell", "00:23:ae": "Dell",
    "00:24:e8": "Dell", "00:25:64": "Dell", "00:26:b9": "Dell",
    # Lenovo
    "00:09:2d": "Lenovo", "04:7d:7b": "Lenovo", "10:02:b5": "Lenovo",
    "14:1f:ba": "Lenovo", "18:5e:0f": "Lenovo", "20:47:47": "Lenovo",
    "24:b6:57": "Lenovo", "28:d2:44": "Lenovo", "2c:54:cf": "Lenovo",
    "34:40:b5": "Lenovo", "3c:97:0e": "Lenovo", "40:78:e4": "Lenovo",
    "48:0f:cf": "Lenovo", "4c:0f:6e": "Lenovo", "54:05:db": "Lenovo",
    "58:8c:ba": "Lenovo", "60:6c:66": "Lenovo", "68:f7:28": "Lenovo",
    "6c:88:14": "Lenovo", "70:5a:0f": "Lenovo", "74:df:bf": "Lenovo",
    "78:2b:46": "Lenovo", "7c:5c:f8": "Lenovo", "80:fa:5b": "Lenovo",
    "84:7b:eb": "Lenovo", "88:70:8c": "Lenovo", "8c:8d:28": "Lenovo",
    "98:fa:9b": "Lenovo", "9c:93:4e": "Lenovo", "a0:48:1c": "Lenovo",
    "a4:4c:c8": "Lenovo", "a8:6d:aa": "Lenovo", "ac:b5:7d": "Lenovo",
    "b0:70:2d": "Lenovo", "b8:ac:6f": "Lenovo", "c8:5b:76": "Lenovo",
    "cc:3d:82": "Lenovo", "d0:53:49": "Lenovo", "d4:85:64": "Lenovo",
    "e8:b4:c8": "Lenovo", "ec:f4:bb": "Lenovo", "f0:de:f1": "Lenovo",
    "f4:8e:38": "Lenovo", "f8:bc:12": "Lenovo",
    # ASUS
    "00:0c:6e": "ASUS", "00:0e:a6": "ASUS", "00:11:2f": "ASUS",
    "00:13:d4": "ASUS", "00:15:f2": "ASUS", "00:17:31": "ASUS",
    "00:18:f3": "ASUS", "00:1a:92": "ASUS", "00:1b:fc": "ASUS",
    "00:1d:60": "ASUS", "00:1e:8c": "ASUS", "00:1f:c6": "ASUS",
    "00:22:15": "ASUS", "00:23:54": "ASUS", "00:24:8c": "ASUS",
    "00:25:22": "ASUS", "00:26:18": "ASUS", "04:92:26": "ASUS",
    "08:60:6e": "ASUS", "0c:9d:92": "ASUS", "10:7b:44": "ASUS",
    "14:da:e9": "ASUS", "18:31:bf": "ASUS", "1c:87:2c": "ASUS",
    "20:cf:30": "ASUS", "24:be:05": "ASUS", "2c:fd:a1": "ASUS",
    "30:85:a9": "ASUS", "34:97:f6": "ASUS", "38:d5:47": "ASUS",
    "3c:97:0e": "ASUS", "40:16:7e": "ASUS", "44:8a:5b": "ASUS",
    "48:5b:39": "ASUS", "4c:ed:fb": "ASUS", "50:46:5d": "ASUS",
    "54:04:a6": "ASUS", "58:11:22": "ASUS", "5c:ff:35": "ASUS",
    "60:45:cb": "ASUS", "64:d1:54": "ASUS", "68:1c:a2": "ASUS",
    "6c:f0:49": "ASUS", "70:85:c2": "ASUS", "74:d0:2b": "ASUS",
    "78:24:af": "ASUS", "7c:10:c9": "ASUS", "80:1f:02": "ASUS",
    "84:a4:23": "ASUS", "88:d7:f6": "ASUS", "8c:89:a5": "ASUS",
    "90:e6:ba": "ASUS", "94:de:80": "ASUS", "9c:5c:8e": "ASUS",
    "a0:f3:c1": "ASUS", "a4:56:02": "ASUS", "a8:5e:45": "ASUS",
    "ac:9e:17": "ASUS", "b0:6e:bf": "ASUS", "b4:2e:99": "ASUS",
    "bc:ee:7b": "ASUS", "c8:60:00": "ASUS", "cc:28:aa": "ASUS",
    "d0:50:99": "ASUS", "d4:5d:64": "ASUS", "d8:50:e6": "ASUS",
    "dc:4a:3e": "ASUS", "e0:3f:49": "ASUS", "e4:02:9b": "ASUS",
    "e8:9c:25": "ASUS", "ec:cb:30": "ASUS", "f0:79:59": "ASUS",
    "f4:6d:04": "ASUS", "f8:32:e4": "ASUS", "fc:aa:14": "ASUS",
}

VENDOR_TO_DEVICE = {
    "Apple":        "Apple Device",
    "Samsung":      "Samsung Device",
    "Xiaomi":       "Xiaomi/Redmi",
    "Huawei":       "Huawei Device",
    "Cisco":        "Cisco Network",
    "TP-Link":      "TP-Link Router/AP",
    "Netgear":      "Netgear Router",
    "Intel":        "PC/Laptop (Intel NIC)",
    "Realtek":      "PC/Desktop (Realtek)",
    "VirtualBox/QEMU": "Virtual Machine",
    "Raspberry Pi": "Raspberry Pi",
    "Amazon":       "Amazon Echo/Fire TV",
    "Google":       "Google Nest/Chromecast",
    "Dell":         "Dell PC/Laptop",
    "Lenovo":       "Lenovo PC/Laptop",
    "ASUS":         "ASUS Device",
}

def _load_trusted_ips() -> List[str]:
    """Load from `local_settings.py` (local only, not on GitHub)."""
    try:
        from . import local_settings as loc
    except ImportError:
        return []
    ips = getattr(loc, "TRUSTED_IPS", None)
    if ips is None:
        return []
    return list(ips)


# Per-machine / network allowlist. Define in `netscan/local_settings.py`
# (copy from `local_settings.example.py`; that file stays local and is gitignored).
TRUSTED_IPS: List[str] = _load_trusted_ips()


def get_advice_for_port(port: int) -> str:
    return SECURITY_ADVICE.get(
        port,
        "No specific advice. Make sure this service is really needed and properly secured."
    )


def is_rogue_device(ip: str) -> bool:
    return ip not in TRUSTED_IPS


def get_mac_for_ip(ip: str) -> Optional[str]:
    """Get MAC address for an IP — reads /proc/net/arp on Linux (fast)."""
    try:
        # Linux fast path
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        return mac.lower()
    except Exception:
        pass

    # Fallback: arp -n / arp -a
    try:
        sys = platform.system().lower()
        cmd = ["arp", "-a", ip] if "windows" in sys else ["arp", "-n", ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        pattern = (r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}"
                   r"[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})")
        match = re.search(pattern, result.stdout)
        if match:
            return match.group(1).lower().replace("-", ":")
    except Exception:
        pass
    return None


def lookup_vendor(mac: str) -> Optional[str]:
    """Lookup vendor name from MAC OUI (first 3 bytes)."""
    if not mac:
        return None
    mac = mac.lower().replace("-", ":").replace(".", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        return None
    oui = ":".join(parts[:3])
    return OUI_DATABASE.get(oui)
