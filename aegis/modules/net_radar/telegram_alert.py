"""Telegram notifier. Silently no-ops when bot token/chat id are unset."""
from __future__ import annotations
import requests

from aegis.config import settings


def send(text: str, markdown: bool = True) -> bool:
    if not settings.tg_bot or not settings.tg_chat:
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{settings.tg_bot}/sendMessage",
            json={
                "chat_id": settings.tg_chat,
                "text": text[:4000],
                "parse_mode": "Markdown" if markdown else None,
                "disable_web_page_preview": True,
            },
            timeout=5,
        )
        return r.ok
    except requests.RequestException:
        return False