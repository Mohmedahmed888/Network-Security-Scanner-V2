from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage
from typing import Optional


class EmailAlert:
    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_pass: Optional[str] = None,
        from_addr: Optional[str] = None,
        to_addr: Optional[str] = None,
    ):
        self.smtp_host = smtp_host or os.environ.get("NETSCAN_SMTP_HOST")
        self.smtp_port = int(smtp_port or os.environ.get("NETSCAN_SMTP_PORT") or 587)
        self.smtp_user = smtp_user or os.environ.get("NETSCAN_SMTP_USER")
        self.smtp_pass = smtp_pass or os.environ.get("NETSCAN_SMTP_PASS")
        self.from_addr = from_addr or os.environ.get("NETSCAN_SMTP_FROM") or self.smtp_user
        self.to_addr = to_addr or os.environ.get("NETSCAN_SMTP_TO")

    def enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_pass and self.to_addr)

    def send(self, title: str, message: str) -> None:
        if not self.enabled():
            return
        msg = EmailMessage()
        msg["Subject"] = title
        msg["From"] = self.from_addr
        msg["To"] = self.to_addr
        msg.set_content(message)
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=12) as s:
            s.starttls()
            s.login(self.smtp_user, self.smtp_pass)
            s.send_message(msg)

