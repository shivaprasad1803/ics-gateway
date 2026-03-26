"""
protocol_bridge.py  —  Protocol Bridge: Modbus TCP ↔ OPC UA
==============================================
Layer 3  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: Bidirectional live-data pipe keeping OPC UA in sync
with Modbus holding registers, and routing SCADA writes back through the
full validation pipeline.
"""
import asyncio
import logging

from asyncua import Client, Node
from asyncua.common.subscription import DataChangeNotificationHandler
from asyncua.ua import DataChangeNotification
from pymodbus.client import AsyncModbusTcpClient

from opcua_server import ICSGatewayOpcuaServer

log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
_HR_TANK_LEVEL  = 0   # Modbus holding-register address: tank level (int)
_HR_VALVE       = 1   # Modbus holding-register address: valve position (int)
_HR_PUMP        = 2   # Modbus holding-register address: pump state (0/1)
_HR_COUNT       = 3   # number of registers to read in one burst
_MODBUS_UNIT    = 1   # Modbus device / unit ID
_NS_URI = "http://ics-security-gateway.local"  # OPC UA namespace URI


class OpcuaWriteHandler(DataChangeNotificationHandler):
    """asyncua subscription callback — forwards OPC UA writes to Modbus.

    When a SCADA client writes to ValvePosition or PumpStatus the asyncua
    server fires ``datachange_notification`` synchronously inside the event
    loop.  We spin off an ``asyncio.create_task`` so the handler returns
    immediately and never blocks the OPC UA event loop.
    """

    def __init__(self, modbus_host: str, modbus_port: int) -> None:
        """Initialise with the coordinates of the target Modbus server."""
        self._host = modbus_host
        self._port = modbus_port
        # Maps OPC UA node-id string → Modbus register address
        self._node_to_register: dict[str, int] = {}

    def register_node(self, node: Node, address: int) -> None:
        """Associate an OPC UA node with a Modbus holding-register address.

        Must be called for every writable node before subscriptions are
        created so the handler knows which register to update.
        """
        self._node_to_register[node.nodeid.to_string()] = address
        log.debug(
            "OpcuaWriteHandler: mapped node %s → HR[%d]",
            node.nodeid.to_string(),
            address,
        )

    def datachange_notification(
        self,
        node: Node,
        val: object,
        data: DataChangeNotification,
    ) -> None:
        """Called by asyncua when a subscribed node value changes.

        Converts *val* to an integer and schedules a Modbus FC6 write on the
        running event loop without blocking it.
        """
        node_id = node.nodeid.to_string()
        address = self._node_to_register.get(node_id)
        if address is None:
            log.warning(
                "OpcuaWriteHandler: unknown node %s — ignoring", node_id
            )
            return

        # Boolean pump state → 0/1; floats truncate to int (scaled upstream).
        # Guard against unexpected OPC UA types (e.g. None, string) — if the
        # conversion fails we log and drop the command rather than silently
        # sending a corrupt value to a physical actuator.
        try:
            int_val = 1 if val is True else (0 if val is False else int(val))
        except (TypeError, ValueError):
            log.error(
                "OpcuaWriteHandler: node %s — cannot convert val=%r to int,"
                " command DROPPED (fail-closed)",
                node_id,
                val,
            )
            return

        log.info(
            "OpcuaWriteHandler: node %s val=%r → Modbus HR[%d]=%d",
            node_id,
            val,
            address,
            int_val,
        )
        asyncio.create_task(
            self._write_modbus(address, int_val),
            name=f"bridge-write-HR{address}-{int_val}",
        )

    async def _write_modbus(self, address: int, value: int) -> None:
        """Open a short-lived Modbus connection and issue one FC6 write."""
        client = AsyncModbusTcpClient(self._host, port=self._port)
        try:
            await client.connect()
            await client.write_register(
                address, value, device_id=_MODBUS_UNIT
            )
            log.debug(
                "OpcuaWriteHandler: wrote HR[%d]=%d via Modbus", address, value
            )
        except Exception:
            log.exception(
                "OpcuaWriteHandler: Modbus write failed HR[%d]=%d",
                address,
                value,
            )
        finally:
            await client.close()


class ModbusToOpcuaBridge:
    """Owns the 500 ms poll loop and the OPC UA write subscription.

    Lifecycle::

        bridge = ModbusToOpcuaBridge(opcua_server)
        await bridge.start()   # connects clients, starts poll + subscription
        await bridge.stop()    # cancels task, closes connections cleanly

    Direction 1 — READ (Modbus → OPC UA)
        Every ``POLL_INTERVAL_S`` seconds the bridge reads HR[0-2] from the
        Modbus server and calls ``opcua_server.update_tank()`` so SCADA
        clients always see fresh physics data.

    Direction 2 — WRITE (OPC UA → Modbus)
        ``OpcuaWriteHandler.datachange_notification`` fires when a SCADA
        client writes ValvePosition or PumpStatus.  The handler forwards the
        validated value back to the Modbus server via a short-lived TCP
        connection.
    """

    POLL_INTERVAL_S: float = 0.5  # 500 ms between Modbus read cycles

    def __init__(
        self,
        opcua_server: ICSGatewayOpcuaServer,
        modbus_host: str = "localhost",
        modbus_port: int = 5020,
        opcua_url: str = "opc.tcp://localhost:4840/ics-gateway/",
    ) -> None:
        """Initialise the bridge (does not connect — call ``start()``).

        Args:
            opcua_server: Running ``ICSGatewayOpcuaServer`` instance whose
                ``update_tank()`` method will be called on every poll.
            modbus_host:  Hostname / IP of the Modbus TCP server.
            modbus_port:  Port of the Modbus TCP server (default 5020).
            opcua_url:    OPC UA endpoint URL for the asyncua client used by
                the write-subscription leg of the bridge.
        """
        self._opcua_server  = opcua_server
        self._modbus_host   = modbus_host
        self._modbus_port   = modbus_port
        self._opcua_url     = opcua_url

        self._modbus_client: AsyncModbusTcpClient | None = None
        self._opcua_client:  Client | None = None
        self._subscription:  object | None = None
        self._poll_task:     asyncio.Task | None = None
        self._write_handler: OpcuaWriteHandler | None = None

    # ── Public lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Connect both clients, subscribe to writable nodes, start polling.

        Safe to call once per instance.  Raises if either connection fails.
        """
        log.info("ModbusToOpcuaBridge: starting …")

        # 1 — Modbus client (persistent connection for the poll loop)
        self._modbus_client = AsyncModbusTcpClient(
            self._modbus_host, port=self._modbus_port
        )
        await self._modbus_client.connect()
        log.info(
            "ModbusToOpcuaBridge: Modbus client connected to %s:%d",
            self._modbus_host,
            self._modbus_port,
        )

        # 2 — OPC UA client (for the write subscription)
        self._opcua_client = Client(url=self._opcua_url)
        await self._opcua_client.connect()
        log.info(
            "ModbusToOpcuaBridge: OPC UA client connected to %s",
            self._opcua_url,
        )

        # 3 — Resolve writable nodes and subscribe to them
        await self._setup_subscription()

        # 4 — Launch the poll loop
        self._poll_task = asyncio.create_task(
            self._poll_loop(), name="bridge-poll-loop"
        )
        log.info("ModbusToOpcuaBridge: poll loop started (%.0f ms interval)",
                 self.POLL_INTERVAL_S * 1000)

    async def stop(self) -> None:
        """Cancel the poll loop and close both client connections cleanly.

        Idempotent — safe to call even if ``start()`` was never invoked or
        was called multiple times.
        """
        log.info("ModbusToOpcuaBridge: stopping …")

        # Cancel poll task
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        self._poll_task = None

        # Delete OPC UA subscription — asyncua's delete() removes all
        # monitored items server-side automatically.  Accessing private
        # _monitored_items would cause a RuntimeWarning in asyncio.
        if self._subscription is not None:
            try:
                await self._subscription.delete()
            except Exception:
                log.debug(
                    "ModbusToOpcuaBridge: subscription cleanup warning",
                    exc_info=True,
                )
            self._subscription = None

        # Close OPC UA client
        if self._opcua_client is not None:
            try:
                await self._opcua_client.disconnect()
            except Exception:
                log.debug(
                    "ModbusToOpcuaBridge: OPC UA disconnect warning",
                    exc_info=True,
                )
            self._opcua_client = None

        # Close Modbus client
        if self._modbus_client is not None:
            try:
                await self._modbus_client.close()
            except Exception:
                log.debug(
                    "ModbusToOpcuaBridge: Modbus close warning", exc_info=True
                )
            self._modbus_client = None

        log.info("ModbusToOpcuaBridge: stopped.")

    # ── Internal helpers ──────────────────────────────────────────────────

    async def _setup_subscription(self) -> None:
        """Resolve OPC UA nodes and create the asyncua data-change subscription."""
        assert self._opcua_client is not None  # called only from start()

        ns_idx = await self._opcua_client.get_namespace_index(_NS_URI)

        valve_node: Node = await self._opcua_client.nodes.root.get_child(
            [
                "0:Objects",
                f"{ns_idx}:Factory",
                f"{ns_idx}:WaterTank_01",
                f"{ns_idx}:ValvePosition",
            ]
        )
        pump_node: Node = await self._opcua_client.nodes.root.get_child(
            [
                "0:Objects",
                f"{ns_idx}:Factory",
                f"{ns_idx}:WaterTank_01",
                f"{ns_idx}:PumpStatus",
            ]
        )

        self._write_handler = OpcuaWriteHandler(
            self._modbus_host, self._modbus_port
        )
        self._write_handler.register_node(valve_node, _HR_VALVE)
        self._write_handler.register_node(pump_node,  _HR_PUMP)

        self._subscription = await self._opcua_client.create_subscription(
            int(self.POLL_INTERVAL_S * 1000),  # ms — match the poll interval
            self._write_handler,
        )
        await self._subscription.subscribe_data_change(
            [valve_node, pump_node]
        )
        log.info(
            "ModbusToOpcuaBridge: subscribed to ValvePosition + PumpStatus"
        )

    async def _poll_loop(self) -> None:
        """Read Modbus HR[0-2] every POLL_INTERVAL_S and push to OPC UA.

        Errors on a single poll are logged and swallowed so the loop survives
        transient Modbus connectivity issues — it does *not* crash the bridge.
        """
        while True:
            await asyncio.sleep(self.POLL_INTERVAL_S)
            await self._do_poll()

    async def _do_poll(self) -> None:
        """Execute one Modbus read → OPC UA update cycle.

        Extracted from the loop so tests can call it directly without needing
        to exercise timing.
        """
        try:
            result = await self._modbus_client.read_holding_registers(
                _HR_TANK_LEVEL, _HR_COUNT, device_id=_MODBUS_UNIT
            )
            if result.isError():
                log.error(
                    "ModbusToOpcuaBridge: Modbus read error — %s", result
                )
                return

            regs = result.registers  # [tank_level_int, valve_int, pump_int]
            tank_level = float(regs[_HR_TANK_LEVEL])
            valve_pos  = float(regs[_HR_VALVE])
            pump_on    = bool(regs[_HR_PUMP])

            await self._opcua_server.update_tank(
                tank_level=tank_level,
                valve_pos=valve_pos,
                pump_on=pump_on,
            )
            log.debug(
                "ModbusToOpcuaBridge: poll → level=%.1f valve=%.1f pump=%s",
                tank_level,
                valve_pos,
                pump_on,
            )
        except asyncio.CancelledError:
            raise  # let the poll loop exit cleanly
        except Exception:
            log.exception("ModbusToOpcuaBridge: poll cycle error — continuing")
