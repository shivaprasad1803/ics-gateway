"""
opcua_server.py  —  OPC UA Server for ICS Security Gateway
==============================================
Layer 2  |  PhysicsGuard ICS Security Gateway
Week 2 deliverable: Expose plant state as an OPC UA address space
                    so SCADA clients can read/write the digital twin.

Address space layout
────────────────────
Objects/
  Factory/
    WaterTank_01/
      TankLevel      Float    READ-ONLY   ← pushed by physics loop
      ValvePosition  Float    READ-WRITE  ← SCADA commands intercepted by GatewayWriteHandler
      PumpStatus     Boolean  READ-WRITE  ← SCADA commands intercepted by GatewayWriteHandler
    TempController_02/
      Temperature    Float    READ-ONLY   ← placeholder (Layer 3)
      HeaterPower    Float    READ-WRITE  ← placeholder (Layer 3)

Lifecycle
─────────
    server = ICSGatewayOpcuaServer(engine=engine, tank=tank)
    await server.init()          # build address space + start listener + wire setters
    asyncio.create_task(server.start())  # run forever
    # ... physics loop calls server.update_tank() every 100 ms ...
    await server.stop()          # clean shutdown

C1 Fix — OPC UA Validation Bypass (CRITICAL)
─────────────────────────────────────────────
Previously ValvePosition and PumpStatus were set_writable(True) with no
interception — any SCADA client could write directly to the OPC UA address
space, bypassing all five Layer 4 rules (R001–R005) entirely.

Fix: GatewayWriteHandler registers synchronous setters via
asyncua's set_attribute_value_setter() API. Every OPC UA write to
ValvePosition or PumpStatus now passes through ValidationEngine.validate()
before the value is committed to the address space. Blocked writes revert
the node to its last known-good value so the address space stays consistent.
The block is logged via the standard logging channel.
"""
import asyncio
import logging
import threading
from typing import TYPE_CHECKING

from asyncua import Server, ua
from asyncua.common.node import Node

if TYPE_CHECKING:
    from src.validation_engine import ValidationEngine
    from src.water_tank import WaterTankController

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────
_DEFAULT_ENDPOINT: str = "opc.tcp://0.0.0.0:4840/ics-gateway/"
_DEFAULT_NAMESPACE: str = "http://ics-security-gateway.local"
_SERVER_NAME: str = "PhysicsGuard ICS Security Gateway"

# Physics loop heartbeat — matches Modbus physics update interval
_POLL_INTERVAL_S: float = 0.1   # 100 ms


class GatewayWriteHandler:
    """
    Intercepts every OPC UA write to ValvePosition and PumpStatus and routes
    it through the ValidationEngine before the value reaches the address space.

    C1 fix: asyncua's set_attribute_value_setter() registers a synchronous
    callable that is invoked INSIDE write_attribute_value() before the value
    is committed.  If the ValidationEngine blocks the command, the setter
    overwrites the incoming DataValue with the last known-good value so the
    node stays consistent.  The OPC UA client receives StatusCode Good but
    the node value does not change — identical behaviour to the Modbus path
    where a blocked write simply leaves the holding register unchanged.

    Thread safety: _last_valve and _last_pump are updated both by SCADA writes
    (asyncio event-loop thread) and by update_last_good() called from the
    physics loop (same asyncio thread via update_tank()).  A threading.Lock
    guards both fields for the rare case where an external thread calls
    update_last_good() directly.

    Usage::

        handler = GatewayWriteHandler(engine, tank)
        # After nodes are created:
        server.iserver.set_attribute_value_setter(valve_nodeid, handler.valve_setter)
        server.iserver.set_attribute_value_setter(pump_nodeid,  handler.pump_setter)
    """

    def __init__(
        self,
        engine: "ValidationEngine",
        tank:   "WaterTankController",
    ) -> None:
        self._engine = engine
        self._tank   = tank
        self._lock   = threading.Lock()
        # Last known-good values — kept in sync by update_last_good() which is
        # called from update_tank() on every physics tick so the revert target
        # is always current even if no SCADA write has happened yet.
        self._last_valve: float = 0.0
        self._last_pump:  bool  = False

    def update_last_good(self, valve: float, pump: bool) -> None:
        """Called by the physics loop (via update_tank) to keep last-good in sync."""
        with self._lock:
            self._last_valve = float(valve)
            self._last_pump  = bool(pump)

    # ── Setters (synchronous — called inside asyncua's write_attribute_value) ──

    def valve_setter(
        self,
        node_data: object,
        attr:      object,
        datavalue: ua.DataValue,
    ) -> None:
        """
        Intercept OPC UA writes to ValvePosition (address=1, HR[1]).

        Runs ValidationEngine against the incoming value using the current
        plant context from WaterTankController.get_state().  On block,
        rewrites datavalue.Value to the last known-good valve position so
        the address space is not corrupted.
        """
        try:
            raw = datavalue.Value.Value if datavalue.Value is not None else None
            if raw is None:
                return
            value = float(raw)
            context = self._tank.get_state()
            result  = self._engine.validate(address=1, value=value, context=context)

            if not result.allowed:
                log.warning(
                    "OPC UA BLOCKED | node=ValvePosition val=%.2f | %s | %s",
                    value, result.rule_id, result.reason,
                )
                with self._lock:
                    revert = self._last_valve
                # Mutate the DataValue in-place — asyncua will store this value
                datavalue.Value = ua.Variant(revert, ua.VariantType.Float)
            else:
                with self._lock:
                    self._last_valve = value
                log.debug("OPC UA ALLOWED | node=ValvePosition val=%.2f", value)

        except Exception:
            log.exception("GatewayWriteHandler.valve_setter raised unexpectedly — write blocked")
            with self._lock:
                revert = self._last_valve
            datavalue.Value = ua.Variant(revert, ua.VariantType.Float)

    def pump_setter(
        self,
        node_data: object,
        attr:      object,
        datavalue: ua.DataValue,
    ) -> None:
        """
        Intercept OPC UA writes to PumpStatus (address=2, HR[2]).

        Same pipeline as valve_setter but for the pump boolean.
        """
        try:
            raw = datavalue.Value.Value if datavalue.Value is not None else None
            if raw is None:
                return
            value = bool(raw)
            context = self._tank.get_state()
            result  = self._engine.validate(address=2, value=float(value), context=context)

            if not result.allowed:
                log.warning(
                    "OPC UA BLOCKED | node=PumpStatus val=%s | %s | %s",
                    value, result.rule_id, result.reason,
                )
                with self._lock:
                    revert = self._last_pump
                datavalue.Value = ua.Variant(revert, ua.VariantType.Boolean)
            else:
                with self._lock:
                    self._last_pump = value
                log.debug("OPC UA ALLOWED | node=PumpStatus val=%s", value)

        except Exception:
            log.exception("GatewayWriteHandler.pump_setter raised unexpectedly — write blocked")
            with self._lock:
                revert = self._last_pump
            datavalue.Value = ua.Variant(revert, ua.VariantType.Boolean)


class ICSGatewayOpcuaServer:
    """OPC UA server that exposes the ICS plant state to SCADA clients.

    Wraps the :class:`asyncua.Server` with a clean lifecycle API and
    explicit node handles so the physics loop (and Layer 3 bridge) can
    push fresh values without re-querying the address space on every tick.

    All shared-state access is protected by an :class:`asyncio.Lock` so
    concurrent callers (physics loop + SCADA write handler) cannot
    interleave partial updates.

    C1 fix: pass ``engine`` and ``tank`` to enable write interception.
    When both are provided, a :class:`GatewayWriteHandler` is wired to
    ValvePosition and PumpStatus during :meth:`init` so all OPC UA writes
    pass through the ValidationEngine before reaching the address space.

    Example usage::

        server = ICSGatewayOpcuaServer(engine=engine, tank=tank)
        await server.init()
        task = asyncio.create_task(server.start())
        # later…
        await server.stop()
        await task
    """

    ENDPOINT: str = _DEFAULT_ENDPOINT
    NAMESPACE: str = _DEFAULT_NAMESPACE

    def __init__(
        self,
        endpoint: str | None = None,
        engine:   "ValidationEngine | None" = None,
        tank:     "WaterTankController | None" = None,
    ) -> None:
        """Create the server wrapper.

        Args:
            endpoint: Override the default OPC UA endpoint URL.
                      Useful in tests that must avoid port 4840.
            engine:   ValidationEngine instance.  When provided together
                      with ``tank``, OPC UA writes to ValvePosition and
                      PumpStatus are intercepted and validated (C1 fix).
            tank:     WaterTankController instance.  Required alongside
                      ``engine`` for write interception.
        """
        self._endpoint: str = endpoint if endpoint is not None else self.ENDPOINT
        self._server: Server | None = None
        self._ns_idx: int = 0
        self._running: bool = False
        self._lock: asyncio.Lock = asyncio.Lock()

        # C1 fix: optional write-interception handler wired during init()
        self._write_handler: GatewayWriteHandler | None = (
            GatewayWriteHandler(engine, tank)
            if engine is not None and tank is not None
            else None
        )

        # Node handles populated during _build_address_space()
        self._tank_level_node: Node | None = None
        self._valve_node: Node | None = None
        self._pump_node: Node | None = None
        self._temp_node: Node | None = None
        self._heater_node: Node | None = None

    # ── Lifecycle ──────────────────────────────────────────────────────

    async def init(self) -> None:
        """Set up the server, register namespace, build address space.

        Creates and starts the underlying :class:`asyncua.Server` so
        OPC UA clients can connect as soon as this coroutine returns.
        Must be called exactly once before any other method.

        Raises:
            RuntimeError: If called more than once without an intervening
                          :meth:`stop`.
        """
        if self._server is not None:
            raise RuntimeError(
                "Server already initialised — call stop() before re-initialising"
            )

        log.info("Initialising OPC UA server on %s", self._endpoint)

        self._server = Server()
        await self._server.init()
        self._server.set_endpoint(self._endpoint)
        self._server.set_server_name(_SERVER_NAME)

        self._ns_idx = await self._server.register_namespace(self.NAMESPACE)
        log.debug(
            "Namespace '%s' registered → idx=%d", self.NAMESPACE, self._ns_idx
        )

        await self._build_address_space()

        # C1 fix: wire write-interception setters now that node handles exist.
        # Must happen AFTER _build_address_space() so _valve_node/_pump_node
        # are populated, and BEFORE server.start() so the setters are active
        # before the first SCADA client can connect.
        if self._write_handler is not None:
            iserver = self._server.iserver
            iserver.set_attribute_value_setter(
                self._valve_node.nodeid, self._write_handler.valve_setter
            )
            iserver.set_attribute_value_setter(
                self._pump_node.nodeid, self._write_handler.pump_setter
            )
            log.info(
                "GatewayWriteHandler wired — OPC UA writes to ValvePosition "
                "and PumpStatus now routed through ValidationEngine (C1 fix)"
            )
        else:
            log.warning(
                "GatewayWriteHandler NOT wired — no engine/tank provided. "
                "OPC UA writes bypass ValidationEngine. Pass engine= and tank= "
                "to ICSGatewayOpcuaServer() to enable write interception."
            )

        await self._server.start()
        log.info("OPC UA server listening on %s", self._endpoint)

    async def start(self) -> None:
        """Block until :meth:`stop` is called (run-forever entry point).

        Intended to be wrapped in ``asyncio.create_task()`` from the
        main entry point.  The physics loop / Layer 3 bridge calls
        :meth:`update_tank` and :meth:`update_temp` concurrently from
        other tasks.

        Raises:
            RuntimeError: If :meth:`init` has not been called first.
        """
        if self._server is None:
            raise RuntimeError("Call init() before start()")

        log.info("OPC UA server run-loop started")
        self._running = True
        try:
            while self._running:
                await asyncio.sleep(_POLL_INTERVAL_S)
        finally:
            log.info("OPC UA server run-loop exited")

    async def stop(self) -> None:
        """Signal the run-loop to exit and cleanly shut down the server.

        Safe to call even if :meth:`start` was never awaited.
        """
        log.info("Stopping OPC UA server…")
        self._running = False
        if self._server is not None:
            await self._server.stop()
            self._server = None
            log.info("OPC UA server stopped")

    # ── Address-space builder (private) ───────────────────────────────

    async def _build_address_space(self) -> None:
        """Create the folder hierarchy and variable nodes.

        Called once from :meth:`init` after the server is ready to
        accept namespace registrations.
        """
        idx: int = self._ns_idx
        objects: Node = self._server.nodes.objects

        # Root factory folder
        factory: Node = await objects.add_folder(idx, "Factory")

        # ── WaterTank_01 ─────────────────────────────────────────────
        tank: Node = await factory.add_folder(idx, "WaterTank_01")

        self._tank_level_node = await tank.add_variable(
            idx, "TankLevel", 0.0,
            varianttype=ua.VariantType.Float,
        )
        # TankLevel is READ-ONLY for OPC UA clients — only the physics
        # loop may update it via update_tank().
        await self._tank_level_node.set_writable(False)

        self._valve_node = await tank.add_variable(
            idx, "ValvePosition", 0.0,
            varianttype=ua.VariantType.Float,
        )
        await self._valve_node.set_writable(True)   # SCADA may write

        self._pump_node = await tank.add_variable(
            idx, "PumpStatus", False,
            varianttype=ua.VariantType.Boolean,
        )
        await self._pump_node.set_writable(True)    # SCADA may write

        log.debug(
            "WaterTank_01: TankLevel(R/O), ValvePosition(R/W), PumpStatus(R/W)"
        )

        # ── TempController_02 ────────────────────────────────────────
        temp_ctrl: Node = await factory.add_folder(idx, "TempController_02")

        self._temp_node = await temp_ctrl.add_variable(
            idx, "Temperature", 0.0,
            varianttype=ua.VariantType.Float,
        )
        await self._temp_node.set_writable(False)   # READ-ONLY

        self._heater_node = await temp_ctrl.add_variable(
            idx, "HeaterPower", 0.0,
            varianttype=ua.VariantType.Float,
        )
        await self._heater_node.set_writable(True)  # READ-WRITE

        log.debug("TempController_02: Temperature(R/O), HeaterPower(R/W)")

    # ── State update API ──────────────────────────────────────────────

    async def update_tank(
        self,
        tank_level: float,
        valve_pos: float,
        pump_on: bool,
    ) -> None:
        """Push fresh WaterTank_01 state into the OPC UA address space.

        Called every ~100 ms by the physics loop or by the Layer 3
        Modbus→OPC UA bridge.  The update is atomic under ``_lock`` so
        a concurrent SCADA read never sees a half-updated state.

        Args:
            tank_level: Tank fill level in percent [0.0, 100.0].
            valve_pos:  Valve opening in percent [0.0, 100.0].
            pump_on:    True when the pump is running.

        Raises:
            RuntimeError: If :meth:`init` has not been called.
        """
        if self._server is None:
            raise RuntimeError("Server not initialised — call init() first")

        async with self._lock:
            await self._tank_level_node.write_value(
                ua.DataValue(ua.Variant(float(tank_level), ua.VariantType.Float))
            )
            await self._valve_node.write_value(
                ua.DataValue(ua.Variant(float(valve_pos), ua.VariantType.Float))
            )
            await self._pump_node.write_value(
                ua.DataValue(ua.Variant(bool(pump_on), ua.VariantType.Boolean))
            )

        # C1 fix: keep the write handler's last-good values in sync with the
        # physics loop so any revert always targets the current plant state,
        # not a stale value from the last SCADA write.
        if self._write_handler is not None:
            self._write_handler.update_last_good(valve_pos, pump_on)

        log.debug(
            "update_tank → level=%.2f  valve=%.2f  pump=%s",
            tank_level, valve_pos, pump_on,
        )

    async def update_temp(
        self,
        temperature: float,
        heater_power: float,
    ) -> None:
        """Push fresh TempController_02 state into the OPC UA address space.

        Placeholder for the Layer 3 bridge.  Structure mirrors
        :meth:`update_tank` so Layer 3 can treat both controllers
        uniformly.

        Args:
            temperature:  Sensor reading in °C (or engineering units).
            heater_power: Heater output in percent [0.0, 100.0].

        Raises:
            RuntimeError: If :meth:`init` has not been called.
        """
        if self._server is None:
            raise RuntimeError("Server not initialised — call init() first")

        async with self._lock:
            await self._temp_node.write_value(
                ua.DataValue(ua.Variant(float(temperature), ua.VariantType.Float))
            )
            await self._heater_node.write_value(
                ua.DataValue(
                    ua.Variant(float(heater_power), ua.VariantType.Float)
                )
            )

        log.debug(
            "update_temp → temperature=%.2f  heater_power=%.2f",
            temperature, heater_power,
        )

    # ── Properties (read-only introspection) ─────────────────────────

    @property
    def namespace_index(self) -> int:
        """Registered namespace index (available after :meth:`init`)."""
        return self._ns_idx

    @property
    def is_running(self) -> bool:
        """True while the run-loop in :meth:`start` is active."""
        return self._running
