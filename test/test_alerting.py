"""
test_alerting.py  —  Unit tests for Layer 5 Alerting Engine
==============================================
Layer 5  |  PhysicsGuard ICS Security Gateway
Week 5 deliverable: 21 tests covering routing logic, Telegram dispatch,
message formatting, error handling, flood cap, and env-var construction.
No real Telegram connection required — all HTTP is mocked.
"""
import os
import threading
import time
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from src.alerting import AlertConfig, AlertManager

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_result(
    severity:  str = "CRITICAL",
    rule_id:   str = "R001",
    reason:    str = "test reason",
    mitre_tag: str = "T0855",
    metadata:  dict | None = None,
) -> MagicMock:
    r = MagicMock()
    r.severity  = severity
    r.rule_id   = rule_id
    r.reason    = reason
    r.mitre_tag = mitre_tag
    r.metadata  = metadata or {}
    return r


def _valid_config() -> AlertConfig:
    return AlertConfig(bot_token="123:TESTTOKEN", chat_id="999888777")


def _make_manager() -> AlertManager:
    return AlertManager(_valid_config())


# ── AlertConfig ───────────────────────────────────────────────────────────────

def test_alertconfig_valid_when_both_set() -> None:
    assert AlertConfig(bot_token="tok", chat_id="123").is_valid() is True


def test_alertconfig_invalid_when_token_empty() -> None:
    assert AlertConfig(bot_token="", chat_id="123").is_valid() is False


def test_alertconfig_invalid_when_chat_id_empty() -> None:
    assert AlertConfig(bot_token="tok", chat_id="").is_valid() is False


def test_alertconfig_invalid_when_both_empty() -> None:
    assert AlertConfig(bot_token="", chat_id="").is_valid() is False


# ── from_env ──────────────────────────────────────────────────────────────────

def test_from_env_reads_environment_variables() -> None:
    env = {
        "PHYSICSGUARD_BOT_TOKEN": "envtoken",
        "PHYSICSGUARD_CHAT_ID":   "envchat",
    }
    with patch.dict(os.environ, env, clear=False):
        manager = AlertManager.from_env()
    assert manager._config.bot_token == "envtoken"
    assert manager._config.chat_id   == "envchat"


def test_from_env_logonly_when_vars_absent() -> None:
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("PHYSICSGUARD_BOT_TOKEN", None)
        os.environ.pop("PHYSICSGUARD_CHAT_ID",   None)
        manager = AlertManager.from_env()
    assert manager._config.is_valid() is False


def test_from_token_constructs_directly() -> None:
    manager = AlertManager.from_token("mytoken", "mychat")
    assert manager._config.bot_token == "mytoken"
    assert manager._config.chat_id   == "mychat"
    assert manager._config.is_valid() is True


# ── Routing logic ─────────────────────────────────────────────────────────────

def test_emergency_triggers_telegram() -> None:
    manager = _make_manager()
    with patch.object(manager, "_dispatch_async") as mock_dispatch:
        manager.send(_make_result(severity="EMERGENCY"))
        mock_dispatch.assert_called_once()


def test_critical_triggers_telegram() -> None:
    manager = _make_manager()
    with patch.object(manager, "_dispatch_async") as mock_dispatch:
        manager.send(_make_result(severity="CRITICAL"))
        mock_dispatch.assert_called_once()


def test_warning_does_not_trigger_telegram() -> None:
    manager = _make_manager()
    with patch.object(manager, "_dispatch_async") as mock_dispatch:
        manager.send(_make_result(severity="WARNING"))
        mock_dispatch.assert_not_called()


def test_info_is_completely_silent() -> None:
    manager = _make_manager()
    with patch.object(manager, "_dispatch_async") as mock_dispatch:
        manager.send(_make_result(severity="INFO"))
        mock_dispatch.assert_not_called()


def test_no_dispatch_when_config_invalid() -> None:
    manager = AlertManager(AlertConfig(bot_token="", chat_id=""))
    with patch.object(manager, "_dispatch_async") as mock_dispatch:
        manager.send(_make_result(severity="CRITICAL"))
        mock_dispatch.assert_not_called()


# ── Message formatting ────────────────────────────────────────────────────────

def test_message_contains_severity() -> None:
    msg = _make_manager()._build_message(_make_result(severity="CRITICAL"))
    assert "CRITICAL" in msg


def test_message_contains_rule_id() -> None:
    msg = _make_manager()._build_message(_make_result(rule_id="R003"))
    assert "R003" in msg


def test_message_contains_mitre_tag() -> None:
    msg = _make_manager()._build_message(_make_result(mitre_tag="T0813"))
    assert "T0813" in msg


def test_message_contains_consequence_when_present() -> None:
    result = _make_result(
        metadata={"consequence": {"description": "OVERFLOW in 4.2s"}}
    )
    msg = _make_manager()._build_message(result)
    assert "Impact" in msg
    assert "OVERFLOW" in msg


def test_message_omits_impact_when_absent() -> None:
    msg = _make_manager()._build_message(_make_result(metadata={}))
    assert "Impact" not in msg


def test_message_is_plain_text_no_markdown() -> None:
    """Message must NOT contain MarkdownV2 syntax — plain text only."""
    result = _make_result(reason="valve %=150.00 outside [0.0, 100.0]")
    msg    = _make_manager()._build_message(result)
    # No backslash escaping of special chars
    assert "\\." not in msg
    assert "\\%" not in msg
    assert "\\[" not in msg


# ── HTTP dispatch ─────────────────────────────────────────────────────────────

def test_send_telegram_posts_to_correct_url() -> None:
    manager = _make_manager()
    result  = _make_result()
    mock_body = b'{"ok":true,"result":{"message_id":1}}'

    with patch("src.alerting.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_body
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
        mock_urlopen.return_value.__exit__  = MagicMock(return_value=False)
        manager._send_telegram(result)

    called_req = mock_urlopen.call_args[0][0]
    assert "api.telegram.org" in called_req.full_url
    assert manager._config.bot_token in called_req.full_url


def test_send_telegram_http_error_does_not_raise() -> None:
    manager = _make_manager()
    exc = urllib.error.HTTPError(
        url="", code=400, msg="Bad Request", hdrs=None, fp=None
    )
    exc.read = lambda: b'{"description":"bad"}'
    with patch("src.alerting.urllib.request.urlopen", side_effect=exc):
        manager._send_telegram(_make_result())  # must not raise


def test_send_telegram_network_error_does_not_raise() -> None:
    manager = _make_manager()
    with patch(
        "src.alerting.urllib.request.urlopen",
        side_effect=urllib.error.URLError("Connection refused"),
    ):
        manager._send_telegram(_make_result())  # must not raise


def test_dispatch_async_uses_daemon_thread() -> None:
    import src.alerting as alerting_module
    manager  = _make_manager()
    spawned: list = []

    original = threading.Thread
    def _capture(*a, **kw):
        t = original(*a, **kw)
        spawned.append(t)
        return t

    with patch("src.alerting.threading.Thread", side_effect=_capture):
        with patch.object(manager, "_send_telegram"):
            manager._dispatch_async(_make_result())

    assert len(spawned) == 1
    assert spawned[0].daemon is True


def test_flood_protection_drops_when_pool_full() -> None:
    import src.alerting as m
    manager = _make_manager()

    # Reset semaphore to known state
    while m._alert_semaphore.acquire(blocking=False):
        pass
    for _ in range(m._MAX_ALERT_THREADS):
        m._alert_semaphore.release()
    # Exhaust all slots
    for _ in range(m._MAX_ALERT_THREADS):
        m._alert_semaphore.acquire(blocking=False)

    try:
        with patch("src.alerting.threading.Thread") as mock_thread:
            manager._dispatch_async(_make_result())
            mock_thread.assert_not_called()
    finally:
        for _ in range(m._MAX_ALERT_THREADS):
            m._alert_semaphore.release()
