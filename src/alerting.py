"""
alerting.py  —  Alerting Engine: Telegram notifications for blocked commands
==============================================
Layer 5  |  PhysicsGuard ICS Security Gateway
Week 5 deliverable: Non-blocking background-thread Telegram dispatch for
EMERGENCY and CRITICAL rule violations. WARNING and INFO are log-only.

Routing table:
  EMERGENCY → Telegram + log
  CRITICAL  → Telegram + log
  WARNING   → log only
  INFO      → silent

Uses stdlib urllib.request only — zero extra dependencies.
Plain-text messages — no MarkdownV2 parse_mode to avoid silent 400 errors.
"""
import json
import logging
import os
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass

log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
_TELEGRAM_API_BASE = "https://api.telegram.org/bot"  # base URL for Bot API
_SEND_MESSAGE_PATH = "/sendMessage"                   # endpoint for text msg
_HTTP_TIMEOUT_S    = 10                               # seconds before giving up
_SEVERITIES_NOTIFY = {"EMERGENCY", "CRITICAL"}        # these get Telegram msg
_SEVERITIES_LOG    = {"WARNING"}                      # log only
_MAX_ALERT_THREADS = 10                               # flood cap
_alert_semaphore   = threading.Semaphore(_MAX_ALERT_THREADS)

# Severity → emoji label
_SEVERITY_EMOJI = {
    "EMERGENCY": "🚨 EMERGENCY",
    "CRITICAL":  "🔴 CRITICAL",
    "WARNING":   "🟡 WARNING",
    "INFO":      "🟢 INFO",
}


@dataclass(frozen=True)
class AlertConfig:
    """Immutable Telegram bot configuration.

    Attributes:
        bot_token: Telegram Bot API token from @BotFather.
        chat_id:   Telegram chat ID to send messages to.
    """
    bot_token: str
    chat_id:   str

    def is_valid(self) -> bool:
        """Return True if both token and chat_id are non-empty."""
        return bool(self.bot_token.strip()) and bool(self.chat_id.strip())


class AlertManager:
    """Dispatches rule-violation alerts to Telegram via a background thread.

    Non-blocking: send() returns immediately. HTTP runs in a daemon thread.

    Usage — from environment variables (recommended)::

        manager = AlertManager.from_env()
        manager.send(result)

    Usage — direct config (no env vars needed)::

        manager = AlertManager.from_token("TOKEN", "CHAT_ID")
        manager.send(result)
    """

    def __init__(self, config: AlertConfig) -> None:
        self._config = config
        if not config.is_valid():
            log.warning(
                "AlertManager: bot_token or chat_id is empty — "
                "Telegram DISABLED (log-only mode)"
            )
        else:
            log.info(
                "AlertManager: ready — chat_id=%s token=%s...",
                config.chat_id,
                config.bot_token[:10],
            )

    @classmethod
    def from_env(cls) -> "AlertManager":
        """Construct from PHYSICSGUARD_BOT_TOKEN and PHYSICSGUARD_CHAT_ID."""
        token   = os.environ.get("PHYSICSGUARD_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("PHYSICSGUARD_CHAT_ID",   "").strip()
        if not token or not chat_id:
            log.warning(
                "AlertManager.from_env: env vars not set — "
                "set PHYSICSGUARD_BOT_TOKEN and PHYSICSGUARD_CHAT_ID"
            )
        return cls(AlertConfig(bot_token=token, chat_id=chat_id))

    @classmethod
    def from_token(cls, bot_token: str, chat_id: str) -> "AlertManager":
        """Construct directly from token and chat_id strings.

        Use this when env vars are not reliable (e.g. running directly).
        """
        return cls(AlertConfig(
            bot_token=bot_token.strip(),
            chat_id=chat_id.strip(),
        ))

    def send(self, result: object) -> None:
        """Route a RuleResult to Telegram and/or log based on severity.

        Routing:
            EMERGENCY → Telegram + log
            CRITICAL  → Telegram + log
            WARNING   → log only
            INFO      → silent
        """
        severity = getattr(result, "severity", "INFO")

        if severity in _SEVERITIES_NOTIFY:
            log.warning(
                "AlertManager [%s] rule=%s mitre=%s — %s",
                severity,
                getattr(result, "rule_id",   "?"),
                getattr(result, "mitre_tag", "?"),
                getattr(result, "reason",    "?"),
            )
            if self._config.is_valid():
                self._dispatch_async(result)
            else:
                log.warning(
                    "AlertManager: Telegram disabled — "
                    "set PHYSICSGUARD_BOT_TOKEN and PHYSICSGUARD_CHAT_ID"
                )

        elif severity in _SEVERITIES_LOG:
            log.warning(
                "AlertManager [%s] rule=%s — %s",
                severity,
                getattr(result, "rule_id", "?"),
                getattr(result, "reason",  "?"),
            )
        # INFO → completely silent

    def _dispatch_async(self, result: object) -> None:
        """Spin off a daemon thread — never blocks the validation hot-path."""
        if not _alert_semaphore.acquire(blocking=False):
            log.warning(
                "AlertManager: thread pool full (%d slots) — "
                "dropping Telegram dispatch for rule=%s",
                _MAX_ALERT_THREADS,
                getattr(result, "rule_id", "?"),
            )
            return
        t = threading.Thread(
            target=self._send_telegram,
            args=(result,),
            daemon=True,
            name=f"alert-{getattr(result, 'rule_id', 'unknown')}",
        )
        t.start()

    def _build_message(self, result: object) -> str:
        """Format a RuleResult into a plain-text Telegram message.

        Plain text only — no MarkdownV2 parse_mode.
        MarkdownV2 requires escaping every special character and a single
        missed character causes Telegram to return HTTP 400 and silently
        drop the message. Plain text is always delivered.
        """
        severity  = getattr(result, "severity",  "UNKNOWN")
        rule_id   = getattr(result, "rule_id",   "?")
        reason    = getattr(result, "reason",    "No reason given")
        mitre_tag = getattr(result, "mitre_tag", "?")
        label     = _SEVERITY_EMOJI.get(severity, "⚠️ ALERT")

        lines = [
            "PhysicsGuard Alert",
            label,
            "",
            f"Rule:   {rule_id}",
            f"MITRE:  {mitre_tag}",
            f"Reason: {reason}",
        ]

        # Consequence metadata if present
        metadata    = getattr(result, "metadata", {}) or {}
        consequence = metadata.get("consequence", {})
        if consequence:
            desc = consequence.get("description", "")
            if desc:
                lines.append(f"Impact: {desc}")

        return "\n".join(lines)

    def _send_telegram(self, result: object) -> None:
        """Blocking HTTP POST — runs in background daemon thread only."""
        try:
            message = self._build_message(result)
            url     = (
                f"{_TELEGRAM_API_BASE}"
                f"{self._config.bot_token}"
                f"{_SEND_MESSAGE_PATH}"
            )
            # NO parse_mode — plain text only, avoids MarkdownV2 400 errors
            payload = json.dumps({
                "chat_id": self._config.chat_id,
                "text":    message,
            }).encode("utf-8")

            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
                body   = json.loads(resp.read())
                ok     = body.get("ok", False)
                msg_id = body.get("result", {}).get("message_id", "?")
                if ok:
                    log.info(
                        "AlertManager: Telegram delivered msg_id=%s rule=%s",
                        msg_id,
                        getattr(result, "rule_id", "?"),
                    )
                else:
                    log.error(
                        "AlertManager: Telegram ok=False body=%s", body
                    )

        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            log.error(
                "AlertManager: Telegram HTTP %d — %s — body: %s",
                exc.code, exc.reason, body,
            )
        except urllib.error.URLError as exc:
            log.error(
                "AlertManager: Telegram network error — %s", exc.reason
            )
        except Exception:
            log.exception(
                "AlertManager: unexpected error sending Telegram alert"
            )
        finally:
            _alert_semaphore.release()
