"""Notification adapters. Mock deliveries are available to the demo harness only."""

from __future__ import annotations

import os
import smtplib
import urllib.parse
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Protocol


class NotificationAdapter(Protocol):
    def send(self, destination: str, code: str, approval_id: str) -> str: ...


class MockNotificationAdapter:
    """In-memory sink for tests/demo; the dashboard never receives its code value."""

    def __init__(self) -> None:
        self.deliveries: list[dict[str, str]] = []

    def send(self, destination: str, code: str, approval_id: str) -> str:
        self.deliveries.append({"destination": destination, "code": code, "approval_id": approval_id})
        return "sent"


@dataclass
class ConfiguredNotificationAdapter:
    """Send via SMTP email or Telegram when configured; no secret is returned to callers."""

    channel: str

    def send(self, destination: str, code: str, approval_id: str) -> str:
        if self.channel == "email":
            host, sender = os.getenv("SMTP_HOST"), os.getenv("SMTP_FROM")
            if not host or not sender:
                raise RuntimeError("Email needs SMTP_HOST and SMTP_FROM configuration")
            message = EmailMessage()
            message["Subject"] = "AI Chakravyuh approval code"
            message["From"], message["To"] = sender, destination
            message.set_content(f"Approval code for request {approval_id}: {code}\nThis code authorizes one exact action and expires shortly.")
            with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
                if os.getenv("SMTP_STARTTLS", "1") == "1":
                    smtp.starttls()
                username, password = os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD")
                if username and password:
                    smtp.login(username, password)
                smtp.send_message(message)
            return "sent"
        if self.channel == "telegram":
            token = os.getenv("TELEGRAM_BOT_TOKEN")
            if not token:
                raise RuntimeError("Telegram needs TELEGRAM_BOT_TOKEN configuration")
            data = urllib.parse.urlencode({"chat_id": destination, "text": f"Approval code for {approval_id}: {code}"}).encode()
            request = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200:
                    raise RuntimeError("Telegram delivery failed")
            return "sent"
        raise ValueError("Notification channel must be 'email' or 'telegram'")


def mask_destination(destination: str) -> str:
    if "@" in destination:
        name, domain = destination.split("@", 1)
        return f"{name[:1]}***@{domain}"
    if len(destination) < 5:
        return "*" * len(destination)
    return f"{destination[:2]}{'*' * (len(destination)-4)}{destination[-2:]}"
