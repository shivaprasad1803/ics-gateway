"""
scada_simulator.py  —  Automated SCADA Client / Traffic Generator
==================================================================
Layer 8 (External)  |  PhysicsGuard ICS Security Gateway

Sends realistic operator commands and scheduled attack campaigns against
the PhysicsGuard Modbus TCP gateway.  Required for the live demo — without
this, the dashboard shows empty stats and the consequence engine is never
exercised.

Run AFTER modbus_server.py is up:
    python src/scada_simulator.py                    # mixed mode (default)
    python src/scada_simulator.py --mode normal      # legit traffic only
    python src/scada_simulator.py --mode attack      # all attacks in sequence
    python src/scada_simulator.py --mode continuous  # run forever (demo mode)

Attacks exercised:
    A01 — Out-of-Range Setpoint         MITRE T0855  R001
    A02 — Rapid Setpoint Change         MITRE T0855  R002
    A03 — Pump Dry-Run Interlock        MITRE T0813  R003
    A06 — DoS Flood (rate throttle)     MITRE T0815  modbus_server rate limiter
    A08 — Command Replay Attack         MITRE T0856  R008
    A09 — Setpoint Oscillation          MITRE T0855  R009
    A10 — Slow-Drip Setpoint Creep      MITRE T0855  R006

PLC register map:
    HR[0]  40001  Tank Level        READ-ONLY   [0-100 %]
    HR[1]  40002  Valve Position    READ-WRITE  [0-100 %]
    HR[2]  40003  Pump State        READ-WRITE  [0=OFF, 1=ON]
    HR[10] 40011  Temperature       READ-ONLY   [0-200 °C]
    HR[11] 40012  Heater Power      READ-WRITE  [0-100 %]

Design notes:
    - Normal valve moves: 2% per 2 s = 1 %/s — under R002's 5 %/s limit
    - Normal heater moves: 5% per 5 s = 1 %/s — legitimate thermal ramping
    - A06 flood: 15 writes in 0.5 s → rate = 30 cmd/s > server limit of 10/s
    - A08 replay: same (addr=1, val=50) twice within 3 s → R008 blocks 2nd
    - A09 oscillation: valve 80%→20%→80%→20%→80% with 20s gaps → R009 blocks
    - A10 slow-drip: 20 steps × 1% / 15 s, R006 fires at step 17
    - Stats printed every N commands so you can watch the block rate climb
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass, field
from typing import Callable

from pymodbus.client import ModbusTcpClient

log = logging.getLogger(__name__)

# ── Connection defaults ────────────────────────────────────────────────────────
SERVER_HOST: str = "localhost"
SERVER_PORT: int = 5020
SLAVE_ID:    int = 1

# ── Timing constants (seconds) ────────────────────────────────────────────────
NORMAL_VALVE_STEP_S:   float = 2.0   # pause between valve increments
NORMAL_HEATER_STEP_S:  float = 5.0   # pause between heater increments
PUMP_HOLD_S:           float = 5.0   # how long pump runs before we stop it
ATTACK_PAUSE_S:        float = 3.0   # pause between individual attacks
SLOW_DRIP_STEP_S:      float = 15.0  # inter-step interval for A10 slow drip
OSCILLATION_STEP_S:    float = 20.0  # inter-step for A09 oscillation
STATS_INTERVAL:        int   = 10    # print stats every N commands


# ── Stats tracker ──────────────────────────────────────────────────────────────

@dataclass
class SimStats:
    """Running totals for the simulator's own counters."""
    total_sent:       int = 0
    normal_sent:      int = 0
    attacks_sent:     int = 0
    attacks_by_type: dict[str, int] = field(default_factory=dict)

    def record(self, category: str = "normal") -> None:
        self.total_sent += 1
        if category == "normal":
            self.normal_sent += 1
        else:
            self.attacks_sent += 1
            self.attacks_by_type[category] = (
                self.attacks_by_type.get(category, 0) + 1
            )

    def print_summary(self) -> None:
        print(
            f"\n  ── Stats ──────────────────────────────────────────\n"
            f"  Total sent   : {self.total_sent}\n"
            f"  Normal ops   : {self.normal_sent}\n"
            f"  Attack probes: {self.attacks_sent}"
        )
        if self.attacks_by_type:
            for name, count in sorted(self.attacks_by_type.items()):
                print(f"    {name:<30} {count}")
        print("  ────────────────────────────────────────────────────")


# ── Connection helpers ─────────────────────────────────────────────────────────

def _connect(host: str = SERVER_HOST, port: int = SERVER_PORT) -> ModbusTcpClient:
    """Connect to the PhysicsGuard Modbus server. Retry 3× with back-off."""
    for attempt in range(1, 4):
        client = ModbusTcpClient(host, port=port)
        if client.connect():
            log.info("SCADA simulator connected to %s:%d", host, port)
            return client
        log.warning(
            "Connection attempt %d/3 failed — retrying in 3 s ...", attempt
        )
        time.sleep(3.0)
    raise ConnectionRefusedError(
        f"Cannot reach PhysicsGuard at {host}:{port}. "
        f"Start it first:  python src/modbus_server.py"
    )


def _write(
    client: ModbusTcpClient,
    address: int,
    value: int,
    label: str = "",
) -> bool:
    """Write one Modbus register. Returns True on success."""
    try:
        r = client.write_register(address, value, device_id=SLAVE_ID)
        if r.isError():
            log.debug("write HR[%d]=%d → Modbus error: %s", address, value, r)
            return False
        if label:
            log.debug("write HR[%d]=%-4d  %s", address, value, label)
        return True
    except Exception as exc:
        log.warning("write HR[%d]=%d exception: %s", address, value, exc)
        return False


def _read_register(client: ModbusTcpClient, address: int) -> float | None:
    """Read a single holding register. Returns None on error."""
    try:
        r = client.read_holding_registers(address=address, count=1, device_id=SLAVE_ID)
        if r.isError():
            return None
        return float(r.registers[0])
    except Exception:
        return None


def _read_tank_level(client: ModbusTcpClient) -> float | None:
    return _read_register(client, 0)


def _read_temperature(client: ModbusTcpClient) -> float | None:
    return _read_register(client, 10)


# ── Normal operations ──────────────────────────────────────────────────────────

def normal_operations(
    client: ModbusTcpClient,
    stats:  SimStats,
    cycles: int = 30,
) -> None:
    """
    Send realistic operator commands — slow valve moves, pump start/stop,
    and temperature controller adjustments.

    Valve increments: 2% per step / 2 s pause → rate = 1 %/s (under R002 5%/s).
    Heater adjustments: 5% per step / 5 s pause → rate = 1 %/s.
    Every 10th cycle: briefly start pump + read sensors.
    """
    valve   = 10   # start at 10%
    heater  = 0    # start with heater off
    valve_direction  = 1
    heater_direction = 1

    for i in range(cycles):
        # ── Valve ramp (PLC_01) ───────────────────────────────────────────────
        valve += valve_direction * 2
        if valve >= 70:
            valve_direction = -1
        elif valve <= 10:
            valve_direction = 1
        valve = max(10, min(70, valve))

        _write(client, 1, valve, label=f"normal valve→{valve}%")
        stats.record("normal")

        # ── Heater ramp (PLC_02) — every 2nd cycle to keep rate low ──────────
        if i % 2 == 0:
            heater += heater_direction * 5
            if heater >= 60:
                heater_direction = -1
            elif heater <= 0:
                heater_direction = 1
            heater = max(0, min(60, heater))
            _write(client, 11, heater, label=f"normal heater→{heater}%")
            stats.record("normal")

        # ── Stats readout ─────────────────────────────────────────────────────
        if stats.total_sent % STATS_INTERVAL == 0:
            level = _read_tank_level(client)
            temp  = _read_temperature(client)
            level_str = f"{level:.0f}%" if level is not None else "??"
            temp_str  = f"{temp:.0f}°C" if temp  is not None else "??"
            log.info(
                "Sent %d commands (%d attacks) | tank=%s temp=%s",
                stats.total_sent, stats.attacks_sent, level_str, temp_str,
            )

        time.sleep(NORMAL_VALVE_STEP_S)

        # ── Every 10th step: pump cycle ───────────────────────────────────────
        if i > 0 and i % 10 == 0:
            level = _read_tank_level(client)
            if level is not None and level >= 15:
                _write(client, 2, 1, label="pump ON")
                stats.record("normal")
                time.sleep(PUMP_HOLD_S)
                _write(client, 2, 0, label="pump OFF")
                stats.record("normal")


# ── Individual attack scenarios ────────────────────────────────────────────────

def _attack_A01_out_of_range(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A01 — Out-of-Range Setpoint (MITRE T0855).
    Writes valve=150 — physical maximum is 100%.
    R001 RangeRule must block this instantly.
    Consequence engine predicts OVERFLOW.
    """
    log.info("  ► A01: Out-of-Range setpoint (valve=150%%)  [expect BLOCKED by R001]")
    _write(client, 1, 150, label="A01 attack valve=150")
    stats.record("A01_OutOfRange")
    time.sleep(0.5)

    # Also try negative (uint16 wrap: 65535 = -1 as signed)
    _write(client, 1, 65535, label="A01 attack valve=-1 (uint16 wrap)")
    stats.record("A01_OutOfRange")


def _attack_A02_rapid_change(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A02 — Rapid Setpoint Change (MITRE T0855).
    Sets valve to 0, waits 2 s (anchors rate baseline), then jumps to 100.
    Rate = 100 %/s >> 5 %/s R002 limit → BLOCKED.
    """
    log.info("  ► A02: Rapid setpoint change (0%%→100%% in <10ms) [expect BLOCKED by R002]")
    _write(client, 1, 0, label="A02 setup valve=0%")
    stats.record("A02_RapidChange")
    time.sleep(2.0)  # anchor rate timer at t0

    _write(client, 1, 100, label="A02 attack valve=100% rapid")
    stats.record("A02_RapidChange")


def _attack_A03_pump_interlock(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A03 — Pump Dry-Run Interlock Bypass (MITRE T0813).
    Blindly sends pump=ON — R003 blocks if tank level < 10%.
    (Effective only if server was started with --initial-level 5.)
    """
    log.info("  ► A03: Pump interlock bypass [expect BLOCKED by R003 if level < 10%%]")
    _write(client, 2, 1, label="A03 attack pump=ON")
    stats.record("A03_PumpInterlock")


def _attack_A06_dos_flood(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A06 — DoS Flood Attack (MITRE T0815).
    Fires 15 rapid writes to the same register in under 0.5 s.
    Server rate limiter (10 cmd/s per IP sliding window) drops excess.
    First 10 may pass; commands 11-15 should be rate-limited.
    """
    log.info(
        "  ► A06: DoS flood (15 writes in <0.5s) "
        "[expect excess DROPPED by rate limiter]"
    )
    for i in range(15):
        val = 20 + (i * 3 % 40)  # slight variation so R008 replay doesn't fire first
        _write(client, 1, val, label=f"A06 flood #{i+1:02d} val={val}")
        stats.record("A06_DoSFlood")
        # No sleep — intentionally rapid-fire to trigger rate limiter


def _attack_A08_replay(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A08 — Command Replay Attack (MITRE T0856).
    Issues valve=50 twice within 3 s.
    R008 ReplayRule records the first and blocks the second.
    """
    log.info("  ► A08: Command replay attack [expect 2nd command BLOCKED by R008]")
    _write(client, 1, 50, label="A08 first shot (legitimate)")
    stats.record("A08_Replay")
    time.sleep(2.0)  # 2 s later — still inside 5 s window
    _write(client, 1, 50, label="A08 replay (same addr+val within window)")
    stats.record("A08_Replay")


def _attack_A09_oscillation(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A09 — Setpoint Oscillation Attack (MITRE T0855).
    Drives valve back-and-forth: 20→80→20→80→20, each step separated
    by OSCILLATION_STEP_S seconds.

    Each individual step:
      - Δ = 60%, dt = 20s → rate = 3%/s → under R002's 5%/s limit ✓
      - Cumulative delta alternates, keeping net drift near 0 → R006 takes longer ✓
    BUT: 4 direction reversals → R009 OscillationRule fires at the 5th command.

    NOTE: Full A09 takes 5 × OSCILLATION_STEP_S seconds (default 100 s).
    Use --fast-oscillation to reduce step interval to 5 s for quick demos.
    """
    log.info(
        "  ► A09: Setpoint oscillation (20%%↔80%% × 5 steps, %ds apart) "
        "[expect BLOCKED by R009 at step 5]",
        int(OSCILLATION_STEP_S),
    )
    # Reset valve to starting position first (counts as step 0, not an attack)
    _write(client, 1, 20, label="A09 reset valve=20%")
    stats.record("normal")  # setup command — legitimate
    time.sleep(OSCILLATION_STEP_S)

    targets = [80, 20, 80, 20, 80]
    for step, target in enumerate(targets, start=1):
        label = (
            f"A09 oscillation step {step}: valve={target}%"
            + (" [expect BLOCKED]" if step == len(targets) else "")
        )
        _write(client, 1, target, label=label)
        stats.record("A09_Oscillation")
        log.info(
            "    A09 step %d/%d: valve→%d%%",
            step, len(targets), target,
        )
        if step < len(targets):
            time.sleep(OSCILLATION_STEP_S)


def _attack_A10_slow_drip(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    A10 — Slow-Drip Setpoint Creep (MITRE T0855).
    Sends valve +1% every SLOW_DRIP_STEP_S seconds, starting from 20%.
    Individual step rate: 1%/15s = 0.067 %/s — well under R002's 5 %/s.
    R006 TemporalRule fires at step 17 (cumulative delta = 16% > 15% limit).

    NOTE: Full A10 takes 20 × 15s = 5 minutes.
    Use --fast-drip to reduce step interval to 1 s for quick demos.
    """
    log.info(
        "  ► A10: Slow-drip attack (%d steps × 1%% / %.0fs) "
        "[expect BLOCKED by R006 at step ~17]",
        20, SLOW_DRIP_STEP_S,
    )
    _write(client, 1, 20, label="A10 reset valve=20%")
    stats.record("A10_SlowDrip")
    time.sleep(SLOW_DRIP_STEP_S)

    for step in range(1, 21):
        valve_val = 20 + step  # 21%, 22%, ..., 40%
        _write(client, 1, valve_val, label=f"A10 step {step:02d} valve={valve_val}%")
        stats.record("A10_SlowDrip")
        log.info(
            "    A10 step %02d: valve=%d%% (cumulative_delta=%d%%)",
            step, valve_val, step,
        )
        if step < 20:
            time.sleep(SLOW_DRIP_STEP_S)


# ── Attack campaign ────────────────────────────────────────────────────────────

def attack_campaign(
    client:             ModbusTcpClient,
    stats:              SimStats,
    include_slow_drip:  bool = True,
    include_oscillation: bool = True,
) -> None:
    """
    Fire all attacks in sequence with pauses between them.

    A10 (slow-drip) and A09 (oscillation) are optional because they are
    time-consuming.  Set the corresponding flag to False for quick runs.
    """
    attacks: list[tuple[str, Callable]] = [
        ("A01", lambda: _attack_A01_out_of_range(client, stats)),
        ("A02", lambda: _attack_A02_rapid_change(client, stats)),
        ("A03", lambda: _attack_A03_pump_interlock(client, stats)),
        ("A06", lambda: _attack_A06_dos_flood(client, stats)),
        ("A08", lambda: _attack_A08_replay(client, stats)),
    ]
    if include_oscillation:
        attacks.append(("A09", lambda: _attack_A09_oscillation(client, stats)))
    if include_slow_drip:
        attacks.append(("A10", lambda: _attack_A10_slow_drip(client, stats)))

    print(f"\n  ══ Attack Campaign ({len(attacks)} scenarios) ══════════════════")
    for name, fn in attacks:
        try:
            fn()
        except Exception as exc:
            log.error("Attack %s raised: %s", name, exc)
        time.sleep(ATTACK_PAUSE_S)

    print("  ══ Campaign complete ═══════════════════════════════════")


# ── Run modes ──────────────────────────────────────────────────────────────────

def run_normal(client: ModbusTcpClient, stats: SimStats) -> None:
    """Normal mode: 200 cycles of legitimate operator traffic on both PLCs."""
    log.info("Mode: NORMAL — sending legitimate operator commands")
    normal_operations(client, stats, cycles=200)
    stats.print_summary()


def run_attack(client: ModbusTcpClient, stats: SimStats) -> None:
    """Attack mode: warm up with 10 legit commands, then fire all attacks."""
    log.info("Mode: ATTACK — warm-up then full attack campaign")
    normal_operations(client, stats, cycles=10)
    attack_campaign(client, stats, include_slow_drip=True, include_oscillation=True)
    stats.print_summary()


def run_mixed(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    Mixed mode: 3 rounds of (20 normal ops → attack campaign).
    Produces realistic 80/20 normal/attack traffic ratio.
    A09 and A10 only in the last round to keep total time manageable.
    """
    log.info("Mode: MIXED — 3 rounds of normal + attacks")
    for round_num in range(1, 4):
        print(f"\n  ── Round {round_num}/3 ───────────────────────────────────────")
        normal_operations(client, stats, cycles=20)
        attack_campaign(
            client, stats,
            include_slow_drip=(round_num == 3),
            include_oscillation=(round_num == 3),
        )
        stats.print_summary()


def run_continuous(client: ModbusTcpClient, stats: SimStats) -> None:
    """
    Continuous mode: run forever, cycling normal traffic and attacks.
    Ideal for keeping the dashboard populated during the defense demo.
    A09 and A10 excluded to keep each loop cycle short (~3 min).
    """
    log.info("Mode: CONTINUOUS — running until Ctrl+C (demo mode)")
    round_num = 0
    while True:
        round_num += 1
        print(f"\n  ── Continuous round {round_num} ─────────────────────────────")
        normal_operations(client, stats, cycles=15)
        attack_campaign(
            client, stats,
            include_slow_drip=False,
            include_oscillation=False,
        )
        stats.print_summary()
        log.info("Sleeping 5 s before next round …")
        time.sleep(5.0)


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="PhysicsGuard SCADA Simulator — traffic generator for live demo"
    )
    parser.add_argument(
        "--mode",
        choices=["normal", "attack", "mixed", "continuous"],
        default="mixed",
        help=(
            "normal=legit only  |  attack=attacks only  |  "
            "mixed=80/20 (default)  |  continuous=run forever (demo)"
        ),
    )
    parser.add_argument(
        "--host", default=SERVER_HOST,
        help=f"Modbus server host (default: {SERVER_HOST})",
    )
    parser.add_argument(
        "--port", type=int, default=SERVER_PORT,
        help=f"Modbus server port (default: {SERVER_PORT})",
    )
    parser.add_argument(
        "--fast-drip", action="store_true",
        help=(
            "Reduce slow-drip (A10) step interval to 1 s instead of 15 s "
            "(R006 still triggers at step ~17 — useful for quick demos)"
        ),
    )
    parser.add_argument(
        "--fast-oscillation", action="store_true",
        help=(
            "Reduce oscillation (A09) step interval to 5 s instead of 20 s "
            "(R009 still triggers at step 5 — useful for quick demos)"
        ),
    )
    args = parser.parse_args()

    if args.fast_drip:
        global SLOW_DRIP_STEP_S
        SLOW_DRIP_STEP_S = 1.0
        log.info("--fast-drip: A10 step interval reduced to 1 s")

    if args.fast_oscillation:
        global OSCILLATION_STEP_S
        OSCILLATION_STEP_S = 5.0
        log.info("--fast-oscillation: A09 step interval reduced to 5 s")

    print("=" * 62)
    print("  PhysicsGuard SCADA Simulator")
    print(f"  Target : {args.host}:{args.port}")
    print(f"  Mode   : {args.mode}")
    print()
    print("  Attacks: A01 A02 A03 A06 A08 A09 A10")
    print("  PLCs   : PLC_01 (water tank) + PLC_02 (temperature)")
    print("=" * 62)

    client = _connect(args.host, args.port)
    stats  = SimStats()

    try:
        if args.mode == "normal":
            run_normal(client, stats)
        elif args.mode == "attack":
            run_attack(client, stats)
        elif args.mode == "continuous":
            run_continuous(client, stats)
        else:
            run_mixed(client, stats)
    except KeyboardInterrupt:
        print("\n  Ctrl+C received — stopping simulator")
    finally:
        client.close()
        stats.print_summary()
        log.info("SCADA simulator stopped")


if __name__ == "__main__":
    main()
