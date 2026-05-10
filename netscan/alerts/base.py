from __future__ import annotations

from typing import Protocol


class AlertSink(Protocol):
    def send(self, title: str, message: str) -> None: ...

