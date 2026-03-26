"""
test_attack_scenarios.py  —  Integration Attack Tests A01–A03
==============================================================
Layer 1  |  PhysicsGuard ICS Security Gateway
Week 1 deliverable: live-server integration tests for the
three baseline attacks against the Modbus server.

Requires: modbus_server.py running on localhost:5020
Run:      python src/modbus_server.py   (in another terminal)
Then:     python tests/test_attack_scenarios.py

pymodbus 3.11.4 VERIFIED patterns:
  ✅ slave=1 on every read/write call
  ✅ result.isError() check before accessing .registers
  ✅ ModbusTcpClient (sync) for test simplicity
  ✅ No bare except — catches specific exceptions

Attack catalogue:
  A01 — Out-of-Range Setpoint    MITRE T0855  CRITICAL
  A02 — Rapid Setpoint Change    MITRE T0855  CRITICAL
  A03 — Pump Interlock Bypass    MITRE T0813  EMERGENCY

Each attack function:
  - Returns True  if the defence held (attack was blocked)
  - Returns False if the attack succeeded (breach — THIS IS BAD)
  - Returns None  for INCONCLUSIVE (setup conditions not met)
"""

import sys
import os
import time
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pymodbus.client import ModbusTcpClient

log = logging.getLogger(__name__)

# ── Server address ─────────────────────────────────────────────────────────────
SERVER_HOST = "localhost"
SERVER_PORT = 5020

# ── Slave / unit ID ────────────────────────────────────────────────────────────
# pymodbus 3.11.x uses slave= as the keyword for the unit/device ID.
SLAVE_ID = 1


# ── Register addresses (0-based internal) ──────────────────────────────────────
ADDR_TANK_LEVEL = 0   # HR[0] — READ-ONLY
ADDR_VALVE      = 1   # HR[1] — valve position
ADDR_PUMP       = 2   # HR[2] — pump state


# ── Connection helper ──────────────────────────────────────────────────────────

def _connect() -> ModbusTcpClient:
    """
    Connect to the Modbus server.
    Raises ConnectionRefusedError with a clear message if server is not running.
    """
    client = ModbusTcpClient(host=SERVER_HOST, port=SERVER_PORT)
    connected = client.connect()
    if not connected:
        raise ConnectionRefusedError(
            f"Cannot connect to PhysicsGuard server at "
            f"{SERVER_HOST}:{SERVER_PORT}. "
            f"Start it with: python src/modbus_server.py"
        )
    return client


# ── Read / write helpers ───────────────────────────────────────────────────────

def _read_hr(client: ModbusTcpClient, address: int, count: int = 1) -> list[int]:
    """
    Read holding registers. Raises IOError if Modbus returns an error.
    Uses device_id=SLAVE_ID (pymodbus 3.11.x keyword).
    Never accesses .registers without isError() check (B09 fix).
    """
    result = client.read_holding_registers(
        address=address,
        count=count,
        device_id=SLAVE_ID,
    )
    if result.isError():
        raise IOError(
            f"Modbus read error at address={address}, count={count}: {result}"
        )
    return result.registers


def _write_hr(client: ModbusTcpClient, address: int, value: int) -> None:
    """
    Write a single holding register.
    Uses device_id=SLAVE_ID (pymodbus 3.11.x keyword).
    """
    result = client.write_register(
        address=address,
        value=value,
        device_id=SLAVE_ID,
    )
    if result.isError():
        raise IOError(
            f"Modbus write error at address={address}, value={value}: {result}"
        )


# ── Attack A01: Out-of-Range Setpoint ─────────────────────────────────────────

def attack_01_out_of_range_setpoint() -> bool | None:
    """
    A01 — Out-of-Range Setpoint (MITRE T0855)

    Attack: Write valve position = 150 (valid range: 0–100).
    Expected: Server blocks the write; register retains prior value.

    Returns:
        True   — defence held (valve unchanged after attack)
        False  — BREACH (valve was set to 150 — should never happen)
        None   — INCONCLUSIVE (connectivity issue)
    """
    try:
        client = _connect()
    except ConnectionRefusedError as e:
        print(f"  A01 INCONCLUSIVE: {e}")
        return None

    try:
        # Read baseline BEFORE attack (B05 fix: compare against actual baseline)
        baseline = _read_hr(client, ADDR_VALVE)[0]
        print(f"  A01 baseline valve = {baseline}%")

        # Attack: write out-of-range value
        _write_hr(client, ADDR_VALVE, 150)
        time.sleep(0.2)  # brief settle (server processes async)

        # Read back — must match baseline, not 150
        after = _read_hr(client, ADDR_VALVE)[0]
        print(f"  A01 valve after attack = {after}%")

        if after == 150:
            print("  A01 ❌ BREACH: valve accepted 150% — R001 failed!")
            return False
        elif after == baseline:
            print(f"  A01 ✅ DEFENCE HELD: valve = {after}% (blocked, retained baseline)")
            return True
        else:
            # Physics loop updated valve while test ran — still not 150, so defence held
            print(f"  A01 ✅ DEFENCE HELD: valve = {after}% (not 150, physics updated)")
            return True

    except IOError as e:
        print(f"  A01 INCONCLUSIVE: {e}")
        return None
    finally:
        client.close()


# ── Attack A02: Rapid Setpoint Change ─────────────────────────────────────────

def attack_02_rapid_setpoint_change() -> bool | None:
    """
    A02 — Rapid Setpoint Change (MITRE T0855)

    Attack: Set valve to 0, wait for rate timer to reset (2 s), then
    immediately jump to 100 — rate = 100 %/s > 5 %/s limit.

    Returns:
        True   — defence held (valve rejected rapid change)
        False  — BREACH (valve jumped to 100 in one command)
        None   — INCONCLUSIVE
    """
    try:
        client = _connect()
    except ConnectionRefusedError as e:
        print(f"  A02 INCONCLUSIVE: {e}")
        return None

    try:
        # Setup: set valve to 0 to establish rate baseline
        print("  A02 setup: setting valve to 0% ...")
        _write_hr(client, ADDR_VALVE, 0)

        # B06 fix: wait 2.0 s to ensure rate timer is anchored at t0
        time.sleep(2.0)

        # Record value just before the attack command
        baseline = _read_hr(client, ADDR_VALVE)[0]
        print(f"  A02 valve before attack = {baseline}%")

        # Attack: jump 0 → 100 in ~0 ms — rate = ~∞ %/s
        _write_hr(client, ADDR_VALVE, 100)
        time.sleep(0.2)

        after = _read_hr(client, ADDR_VALVE)[0]
        print(f"  A02 valve after attack = {after}%")

        if after == 100:
            print("  A02 ❌ BREACH: valve accepted rapid jump to 100% — R002 failed!")
            return False
        else:
            print(f"  A02 ✅ DEFENCE HELD: valve = {after}% (rapid change blocked)")
            return True

    except IOError as e:
        print(f"  A02 INCONCLUSIVE: {e}")
        return None
    finally:
        client.close()


# ── Attack A03: Pump Interlock Bypass ─────────────────────────────────────────

def attack_03_pump_interlock_bypass() -> bool | None:
    """
    A03 — Pump Dry-Run Interlock Bypass (MITRE T0813)

    Attack: Start the pump when tank level is already below 10%.
    The interlock must prevent this to avoid dry-running the pump.

    Pre-condition: server must be started with a low initial level:
        python src/modbus_server.py --initial-level 5

    Why we do NOT drain the tank ourselves:
        Draining by starting the pump at 50% is legitimate operator behaviour —
        R003 allows it because level >= 10.  Doing that inside the test would
        not simulate an attack at all; it would just exercise normal operation.
        The attack being tested is a blind pump-ON command when the tank is
        ALREADY critically low — the attacker does not get to set up conditions
        first.  The server must be started in the low-level state.

    Returns:
        True   — defence held (pump start blocked at low level)
        False  — BREACH (pump started at low level — R003 failed)
        None   — INCONCLUSIVE (tank too high; restart server with --initial-level 5)
    """
    try:
        client = _connect()
    except ConnectionRefusedError as e:
        print(f"  A03 INCONCLUSIVE: {e}")
        return None

    try:
        level = _read_hr(client, ADDR_TANK_LEVEL)[0]
        print(f"  A03 current tank level = {level}%")

        # Interlock only testable when tank is already below 10%.
        # We do NOT drain it ourselves — see docstring above.
        if level >= 10:
            print(
                f"  A03 INCONCLUSIVE: tank at {level}% (need < 10% to test interlock).\n"
                f"  ➜  Restart the server at a low level and re-run:\n"
                f"       python src/modbus_server.py --initial-level 5"
            )
            return None

        # Record pump state before attack
        pump_before = _read_hr(client, ADDR_PUMP)[0]
        print(f"  A03 pump state before attack = {pump_before}")

        # Attack: blindly attempt to start pump at critically low level
        _write_hr(client, ADDR_PUMP, 1)
        time.sleep(0.2)

        pump_after = _read_hr(client, ADDR_PUMP)[0]
        print(f"  A03 pump state after attack = {pump_after}")

        if pump_after == 1:
            print(
                "  A03 ❌ BREACH: pump started at low tank level — "
                "R003 interlock failed!"
            )
            return False
        else:
            print(
                f"  A03 ✅ DEFENCE HELD: pump = {pump_after} "
                f"(start blocked at {level}% level)"
            )
            return True

    except IOError as e:
        print(f"  A03 INCONCLUSIVE: {e}")
        return None
    finally:
        client.close()


# ── Main: run all attacks and report ──────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.WARNING,  # suppress pymodbus INFO noise in test output
        format="%(levelname)-8s %(message)s",
    )

    print()
    print("=" * 62)
    print("  PhysicsGuard — Attack Scenario Tests  |  Layer 1")
    print(f"  pymodbus 3.11.4  |  device_id=1   |  A01–A03")
    print("=" * 62)

    attacks = [
        ("A01", "Out-of-Range Setpoint  ", "T0855", attack_01_out_of_range_setpoint),
        ("A02", "Rapid Setpoint Change  ", "T0855", attack_02_rapid_setpoint_change),
        ("A03", "Pump Interlock Bypass  ", "T0813", attack_03_pump_interlock_bypass),
    ]

    results: list[tuple[str, str, bool | None]] = []

    for attack_id, name, mitre, fn in attacks:
        print()
        print(f"── {attack_id}: {name} ({mitre}) ──────────────────")
        result = fn()
        results.append((attack_id, name, result))

    # Summary table
    print()
    print("=" * 62)
    print("  SUMMARY")
    print("=" * 62)
    print(f"  {'ID':<5} {'Attack':<26} {'Result'}")
    print(f"  {'-'*5} {'-'*26} {'-'*20}")

    all_pass   = True
    any_breach = False

    for attack_id, name, result in results:
        if result is True:
            status = "✅  DEFENCE HELD"
        elif result is False:
            status = "❌  BREACH — FIX REQUIRED"
            any_breach = True
            all_pass = False
        else:
            status = "⚠️   INCONCLUSIVE"
            all_pass = False

        print(f"  {attack_id:<5} {name:<26} {status}")

    print()
    if any_breach:
        print("  ❌  BREACHES DETECTED — Review validation rules")
        raise SystemExit(1)
    elif all_pass:
        print("  ✅  ALL DEFENCES HELD — Layer 1 verified")
    else:
        print("  ⚠️   Some tests inconclusive — check server state and re-run")
    print("=" * 62)


if __name__ == "__main__":
    main()
