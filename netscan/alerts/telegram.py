from __future__ import annotations

import os
from typing import Optional

import requests


class TelegramAlert:
    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        self.bot_token = bot_token or os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = chat_id or os.environ.get("TELEGRAM_CHAT_ID")

    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send(self, title: str, message: str) -> None:
        if not self.enabled():
            return
        text = f"*{title}*\n{message}"
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        requests.post(
            url,
            json={"chat_id": self.chat_id, "text": text, "parse_mode": "Markdown"},
            timeout=8,
        )

