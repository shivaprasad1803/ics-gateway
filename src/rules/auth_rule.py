"""
auth_rule.py  —  R004 Source IP Whitelist Rule
===============================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: block write commands from unauthorised source IPs.

Detects attacks:
  A05 — Unauthorised Command Injection  (MITRE T0817)
  A11 — Man-in-the-Middle Command Relay (MITRE T0817)

Priority design:
  R004 runs at priority=5 — BEFORE all other rules (R001=10, R002=20, R003=30).
  Rationale: IP authentication is the cheapest and most decisive gate.
  There is no value in running physics-aware rules on a command from
  an attacker's machine. Fail-fast on identity before checking content.

Source IP in context:
  context["source_ip"] is populated by the Modbus server layer from the
  client transport address. In pymodbus 3.11.4, the framer exposes this
  via the request context. If source_ip is absent from context (e.g. in
  unit tests or internal calls), the whitelist check is SKIPPED — this
  is a deliberate design choice to avoid blocking internal physics-loop
  writes that do not carry a source IP.

  IMPORTANT: If whitelist is non-empty and source_ip IS present in context
  but is not in the whitelist, the command is BLOCKED.
  If whitelist is empty, ALL sources are allowed (opt-in security model —
  operator has not configured IP restrictions yet).

MITRE ATT&CK for ICS:
  T0817 — Drive-by Compromise: adversary gains access to OT network and
  sends commands from an unauthorised endpoint.
"""

import logging
from typing import Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_CRITICAL,
)

log = logging.getLogger(__name__)


class AuthRule(BaseRule):
    """
    R004 — Source IP Whitelist Rule  (MITRE T0817)

    Blocks any write command whose source IP is not in the configured
    whitelist. If the whitelist is empty, all sources are permitted
    (operator opt-in model — prevents locking out misconfigured systems
    on first deployment).

    The rule guards ALL register addresses when address is None (default),
    or a specific address when explicitly set.

    Usage::

        # Guard all registers from unknown sources
        rule = AuthRule(allowed_ips={"127.0.0.1", "192.168.1.10"})
        ctx  = {"source_ip": "10.0.0.99", "tank_level": 50.0}
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        assert result.allowed is False   # 10.0.0.99 not whitelisted

        # No IP in context → skip (internal call)
        ctx2 = {"tank_level": 50.0}
        result2 = rule.evaluate(address=1, value=50.0, context=ctx2)
        assert result2.allowed is True   # no source_ip → skip

        # Empty whitelist → allow all
        rule2 = AuthRule(allowed_ips=set())
        result3 = rule2.evaluate(address=1, value=50.0, context=ctx)
        assert result3.allowed is True
    """

    rule_id:   str = "R004"
    priority:  int = 5         # Runs FIRST — cheapest gate, most decisive
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0817"   # Drive-by Compromise

    def __init__(
        self,
        allowed_ips: set[str] | list[str] | None = None,
        address:     int | None = None,
        label:       str = "IP whitelist",
    ) -> None:
        """
        Args:
            allowed_ips : set of permitted source IP strings.
                          None or empty set → allow all (opt-in model).
                          e.g. {"127.0.0.1", "192.168.1.10"}
            address     : register address to guard, or None to guard all.
                          None is the normal production setting.
            label       : description for log/reason strings
        """
        if allowed_ips is None:
            self._allowed_ips: frozenset[str] = frozenset()
        else:
            self._allowed_ips = frozenset(allowed_ips)

        self.address = address   # None = guard all addresses
        self.label   = label

    @property
    def allowed_ips(self) -> frozenset[str]:
        """Read-only view of the whitelist — immutable after construction."""
        return self._allowed_ips

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,   # unused — satisfies BaseRule contract
    ) -> RuleResult:
        """
        Block if source_ip is present in context and not in whitelist.

        Skip conditions (pass immediately):
          1. Rule targets a specific address and this is a different one
          2. Whitelist is empty (opt-in model — not yet configured)
          3. source_ip is not in context (internal call, physics loop, etc.)

        Complexity: O(1) — frozenset lookup.
        """
        # Optional address filter
        if self.address is not None and address != self.address:
            return pass_result(
                self.rule_id,
                f"R004 skipped (reg {address} ≠ {self.address})",
            )

        # Empty whitelist → allow all (opt-in model, not yet configured)
        if not self._allowed_ips:
            return pass_result(
                self.rule_id,
                "R004 skipped (whitelist empty — opt-in not configured)",
            )

        source_ip: str | None = context.get("source_ip")   # type: ignore[assignment]

        # No source_ip in context → internal/physics call, skip check
        if source_ip is None:
            return pass_result(
                self.rule_id,
                "R004 skipped (no source_ip in context — internal call)",
            )

        source_ip = str(source_ip).strip()

        if source_ip in self._allowed_ips:
            return pass_result(
                self.rule_id,
                f"R004 PASS | {self.label} | "
                f"source_ip {source_ip!r} is authorised",
            )

        reason = (
            f"R004 AUTH VIOLATION | {self.label} | "
            f"source_ip {source_ip!r} not in whitelist | "
            f"MITRE {self.mitre_tag}"
        )
        log.warning(
            "AuthRule: BLOCKED unauthorised source | ip=%r | addr=%d val=%.2f",
            source_ip, address, value,
        )
        return block_result(
            rule_id=self.rule_id,
            reason=reason,
            severity=self.severity,
            mitre_tag=self.mitre_tag,
            metadata={
                "source_ip":   source_ip,
                "address":     address,
                "value":       value,
                "allowed_ips": sorted(self._allowed_ips),
            },
        )
