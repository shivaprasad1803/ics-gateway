"""
test_protocol_bridge.py  —  Unit tests for Layer 3 Protocol Bridge
==============================================
Layer 3  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: 14 tests covering poll loop, write handler, error
handling, and bridge lifecycle — no running servers required.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest

from src.protocol_bridge import ModbusToOpcuaBridge, OpcuaWriteHandler

# ── Helpers / shared fixtures ─────────────────────────────────────────────────


def _make_modbus_result(registers: list[int]) -> MagicMock:
    """Return a fake Modbus read result with the given register values."""
    result = MagicMock()
    result.isError.return_value = False
    result.registers = registers
    return result


def _make_error_result() -> MagicMock:
    """Return a fake Modbus result that signals an error."""
    result = MagicMock()
    result.isError.return_value = True
    return result


def _make_opcua_server() -> AsyncMock:
    """Return a mock ICSGatewayOpcuaServer with an async update_tank()."""
    server = AsyncMock()
    server.update_tank = AsyncMock()
    return server


@pytest.fixture()
def opcua_server() -> AsyncMock:
    return _make_opcua_server()


@pytest.fixture()
def bridge(opcua_server: AsyncMock) -> ModbusToOpcuaBridge:
    """Bridge instance pre-wired with a mock OPC UA server.

    Clients are NOT connected — individual tests inject mocks directly.
    """
    return ModbusToOpcuaBridge(
        opcua_server=opcua_server,
        modbus_host="localhost",
        modbus_port=5020,
        opcua_url="opc.tcp://localhost:4840/ics-gateway/",
    )


# ── T01  Bridge starts without error ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_bridge_starts_without_error(opcua_server: AsyncMock) -> None:
    """Bridge.start() connects both clients and launches the poll task."""
    bridge = ModbusToOpcuaBridge(opcua_server=opcua_server)

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()

    mock_opcua_client = AsyncMock()
    mock_opcua_client.get_namespace_index = AsyncMock(return_value=2)
    mock_opcua_client.nodes = MagicMock()

    # Build fake node objects with a nodeid attribute
    def _fake_node(name: str) -> MagicMock:
        n = MagicMock()
        n.nodeid = MagicMock()
        n.nodeid.to_string.return_value = f"ns=2;s={name}"
        return n

    mock_opcua_client.nodes.root.get_child = AsyncMock(
        side_effect=[_fake_node("ValvePosition"), _fake_node("PumpStatus")]
    )
    mock_sub = AsyncMock()
    mock_opcua_client.create_subscription = AsyncMock(return_value=mock_sub)
    mock_sub.subscribe_data_change = AsyncMock()

    with (
        patch(
            "src.protocol_bridge.AsyncModbusTcpClient",
            return_value=mock_modbus,
        ),
        patch(
            "src.protocol_bridge.Client",
            return_value=mock_opcua_client,
        ),
    ):
        await bridge.start()
        assert bridge._poll_task is not None, "poll task should be created"
        assert not bridge._poll_task.done(), "poll task should be running"

    await bridge.stop()


# ── T02  Bridge stops cleanly ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bridge_stops_cleanly(opcua_server: AsyncMock) -> None:
    """Bridge.stop() cancels the poll task and closes both connections."""
    bridge = ModbusToOpcuaBridge(opcua_server=opcua_server)

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.close = AsyncMock()

    mock_opcua_client = AsyncMock()
    mock_opcua_client.get_namespace_index = AsyncMock(return_value=2)
    mock_opcua_client.disconnect = AsyncMock()

    def _fake_node(name: str) -> MagicMock:
        n = MagicMock()
        n.nodeid = MagicMock()
        n.nodeid.to_string.return_value = f"ns=2;s={name}"
        return n

    mock_opcua_client.nodes.root.get_child = AsyncMock(
        side_effect=[_fake_node("ValvePosition"), _fake_node("PumpStatus")]
    )
    mock_sub = AsyncMock()
    mock_opcua_client.create_subscription = AsyncMock(return_value=mock_sub)
    mock_sub.subscribe_data_change = AsyncMock()
    mock_sub.delete = AsyncMock()

    with (
        patch("src.protocol_bridge.AsyncModbusTcpClient",
              return_value=mock_modbus),
        patch("src.protocol_bridge.Client", return_value=mock_opcua_client),
    ):
        await bridge.start()
        await bridge.stop()

    assert bridge._poll_task is None, "poll task should be cleared after stop"
    assert bridge._modbus_client is None, "Modbus client should be cleared"
    assert bridge._opcua_client is None, "OPC UA client should be cleared"
    mock_modbus.close.assert_called_once()
    mock_opcua_client.disconnect.assert_called_once()


# ── T03  Poll loop calls update_tank with correct values ─────────────────────


@pytest.mark.asyncio
async def test_poll_loop_calls_update_tank(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """_do_poll() reads HR[0-2] and calls update_tank with mapped values."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_modbus_result([55, 30, 1])
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()

    opcua_server.update_tank.assert_awaited_once_with(
        tank_level=55.0,
        valve_pos=30.0,
        pump_on=True,
    )


# ── T04  Poll loop runs at correct interval ───────────────────────────────────


@pytest.mark.asyncio
async def test_poll_interval(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """_poll_loop calls _do_poll exactly N times for N sleep cycles."""
    poll_count = 0

    async def _fake_poll() -> None:
        nonlocal poll_count
        poll_count += 1

    bridge._do_poll = _fake_poll  # type: ignore[method-assign]

    sleep_count = 0
    original_sleep = asyncio.sleep

    async def _fake_sleep(delay: float) -> None:
        nonlocal sleep_count
        sleep_count += 1
        if sleep_count >= 3:
            raise asyncio.CancelledError  # stop after 3 cycles
        await original_sleep(0)  # yield to event loop but don't actually wait

    with patch("src.protocol_bridge.asyncio.sleep", side_effect=_fake_sleep):
        with pytest.raises(asyncio.CancelledError):
            await bridge._poll_loop()

    assert poll_count == 2, (
        f"Expected 2 poll calls for 2 completed sleep cycles, got {poll_count}"
    )


# ── T05  HR[0] (tank_level) maps correctly ────────────────────────────────────


@pytest.mark.asyncio
async def test_tank_level_mapped_correctly(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """HR[0] integer is converted to float and passed as tank_level."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_modbus_result([72, 0, 0])
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()

    args = opcua_server.update_tank.call_args
    assert args.kwargs["tank_level"] == 72.0, (
        "HR[0]=72 should map to tank_level=72.0"
    )


# ── T06  HR[1] (valve_int) maps correctly ────────────────────────────────────


@pytest.mark.asyncio
async def test_valve_position_mapped_correctly(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """HR[1] integer is converted to float and passed as valve_pos."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_modbus_result([0, 45, 0])
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()

    args = opcua_server.update_tank.call_args
    assert args.kwargs["valve_pos"] == 45.0, (
        "HR[1]=45 should map to valve_pos=45.0"
    )


# ── T07  HR[2]=0 maps to pump_on=False ───────────────────────────────────────


@pytest.mark.asyncio
async def test_pump_int_zero_maps_to_false(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """HR[2]=0 should map to pump_on=False."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_modbus_result([0, 0, 0])
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()

    args = opcua_server.update_tank.call_args
    assert args.kwargs["pump_on"] is False, "HR[2]=0 must map to pump_on=False"


# ── T08  HR[2]=1 maps to pump_on=True ────────────────────────────────────────


@pytest.mark.asyncio
async def test_pump_int_one_maps_to_true(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """HR[2]=1 should map to pump_on=True."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_modbus_result([0, 0, 1])
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()

    args = opcua_server.update_tank.call_args
    assert args.kwargs["pump_on"] is True, "HR[2]=1 must map to pump_on=True"


# ── T09  OpcuaWriteHandler forwards valve write ───────────────────────────────


@pytest.mark.asyncio
async def test_write_handler_forwards_valve_write() -> None:
    """datachange_notification for ValvePosition triggers a Modbus HR[1] write."""
    handler = OpcuaWriteHandler("localhost", 5020)

    valve_node = MagicMock()
    valve_node.nodeid.to_string.return_value = "ns=2;s=ValvePosition"
    handler.register_node(valve_node, 1)  # HR[1]

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.write_register = AsyncMock()
    mock_modbus.close = AsyncMock()

    data = MagicMock()

    with patch(
        "src.protocol_bridge.AsyncModbusTcpClient", return_value=mock_modbus
    ):
        handler.datachange_notification(valve_node, 75, data)
        # Allow the created task to run
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    mock_modbus.write_register.assert_awaited_once_with(
        1, 75, device_id=1
    )


# ── T10  OpcuaWriteHandler forwards pump write ────────────────────────────────


@pytest.mark.asyncio
async def test_write_handler_forwards_pump_write() -> None:
    """datachange_notification for PumpStatus (True) triggers HR[2]=1 write."""
    handler = OpcuaWriteHandler("localhost", 5020)

    pump_node = MagicMock()
    pump_node.nodeid.to_string.return_value = "ns=2;s=PumpStatus"
    handler.register_node(pump_node, 2)  # HR[2]

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.write_register = AsyncMock()
    mock_modbus.close = AsyncMock()

    data = MagicMock()

    with patch(
        "src.protocol_bridge.AsyncModbusTcpClient", return_value=mock_modbus
    ):
        handler.datachange_notification(pump_node, True, data)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    mock_modbus.write_register.assert_awaited_once_with(
        2, 1, device_id=1
    )


# ── T11  OpcuaWriteHandler uses device_id=1 ──────────────────────────────────


@pytest.mark.asyncio
async def test_write_handler_uses_correct_device_id() -> None:
    """All Modbus writes from OpcuaWriteHandler must use device_id=1."""
    handler = OpcuaWriteHandler("localhost", 5020)

    node = MagicMock()
    node.nodeid.to_string.return_value = "ns=2;s=ValvePosition"
    handler.register_node(node, 1)

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.write_register = AsyncMock()
    mock_modbus.close = AsyncMock()

    data = MagicMock()

    with patch(
        "src.protocol_bridge.AsyncModbusTcpClient", return_value=mock_modbus
    ):
        handler.datachange_notification(node, 50, data)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    _, kwargs = mock_modbus.write_register.call_args
    assert kwargs.get("device_id") == 1, (
        "Modbus writes must use device_id=1"
    )


# ── T12  Modbus read failure is logged and does not crash poll ────────────────


@pytest.mark.asyncio
async def test_modbus_read_error_does_not_crash_poll(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """A Modbus error result is swallowed — update_tank is NOT called."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        return_value=_make_error_result()
    )
    bridge._modbus_client = mock_modbus

    # Should not raise
    await bridge._do_poll()

    opcua_server.update_tank.assert_not_awaited()


# ── T13  Two consecutive polls both reach update_tank ────────────────────────


@pytest.mark.asyncio
async def test_two_consecutive_polls_update_opcua_twice(
    bridge: ModbusToOpcuaBridge, opcua_server: AsyncMock
) -> None:
    """update_tank is called once per poll — two polls → two calls."""
    mock_modbus = AsyncMock()
    mock_modbus.read_holding_registers = AsyncMock(
        side_effect=[
            _make_modbus_result([10, 20, 0]),
            _make_modbus_result([15, 25, 1]),
        ]
    )
    bridge._modbus_client = mock_modbus

    await bridge._do_poll()
    await bridge._do_poll()

    assert opcua_server.update_tank.await_count == 2, (
        "Two successful polls must each call update_tank once"
    )


# ── T14  Bridge can be started and stopped twice (idempotent stop) ────────────


@pytest.mark.asyncio
async def test_bridge_start_stop_twice(opcua_server: AsyncMock) -> None:
    """stop() is idempotent — calling it twice must not raise."""
    bridge = ModbusToOpcuaBridge(opcua_server=opcua_server)

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.close = AsyncMock()

    mock_opcua_client = AsyncMock()
    mock_opcua_client.get_namespace_index = AsyncMock(return_value=2)
    mock_opcua_client.disconnect = AsyncMock()

    def _fake_node(name: str) -> MagicMock:
        n = MagicMock()
        n.nodeid = MagicMock()
        n.nodeid.to_string.return_value = f"ns=2;s={name}"
        return n

    mock_opcua_client.nodes.root.get_child = AsyncMock(
        side_effect=[
            _fake_node("ValvePosition"),
            _fake_node("PumpStatus"),
        ]
    )
    mock_sub = AsyncMock()
    mock_opcua_client.create_subscription = AsyncMock(return_value=mock_sub)
    mock_sub.subscribe_data_change = AsyncMock()
    mock_sub.delete = AsyncMock()

    with (
        patch("src.protocol_bridge.AsyncModbusTcpClient",
              return_value=mock_modbus),
        patch("src.protocol_bridge.Client", return_value=mock_opcua_client),
    ):
        await bridge.start()
        await bridge.stop()   # first stop — normal
        await bridge.stop()   # second stop — must not raise


# ── T15  Bad OPC UA type is fail-closed — no Modbus write fired ───────────────


@pytest.mark.asyncio
async def test_write_handler_bad_type_is_fail_closed() -> None:
    """A non-numeric OPC UA value must be DROPPED — Modbus write must NOT fire."""
    handler = OpcuaWriteHandler("localhost", 5020)

    node = MagicMock()
    node.nodeid.to_string.return_value = "ns=2;s=ValvePosition"
    handler.register_node(node, 1)

    mock_modbus = AsyncMock()
    mock_modbus.connect = AsyncMock()
    mock_modbus.write_register = AsyncMock()
    mock_modbus.close = AsyncMock()

    data = MagicMock()

    with patch(
        "src.protocol_bridge.AsyncModbusTcpClient", return_value=mock_modbus
    ):
        # "OPEN" is a string — cannot safely become a Modbus register int
        handler.datachange_notification(node, "OPEN", data)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    mock_modbus.write_register.assert_not_awaited()
