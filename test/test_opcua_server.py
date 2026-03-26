"""
test_opcua_server.py  —  Test suite for ICSGatewayOpcuaServer
==============================================
Layer 2  |  PhysicsGuard ICS Security Gateway
Week 2 deliverable: ≥12 pytest-asyncio tests verifying the OPC UA
                    address space, read/write access, update API,
                    and clean lifecycle management.

Run with:
    pytest tests/test_opcua_server.py -v
    python tests/test_opcua_server.py        # standalone bridge
"""
import asyncio
import logging
import sys
import os

import pytest
import pytest_asyncio
from asyncua import Client, ua
from asyncua.ua import UaStatusCodeError

# ── Path setup (allows running as `python tests/test_opcua_server.py`) ──
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.opcua_server import ICSGatewayOpcuaServer

log = logging.getLogger(__name__)

# ── Test configuration ────────────────────────────────────────────────
#  Use port 4841 so tests never conflict with a production server on 4840.
_TEST_PORT: int = 4841
_TEST_ENDPOINT: str = f"opc.tcp://0.0.0.0:{_TEST_PORT}/ics-gateway/"
_TEST_URL: str = f"opc.tcp://localhost:{_TEST_PORT}/ics-gateway/"


# ─────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def server() -> ICSGatewayOpcuaServer:
    """Provide a started OPC UA server; ensure clean shutdown after each test."""
    srv = ICSGatewayOpcuaServer(endpoint=_TEST_ENDPOINT)
    await srv.init()
    yield srv
    await srv.stop()


@pytest_asyncio.fixture
async def client(server: ICSGatewayOpcuaServer) -> Client:
    """Provide a connected asyncua Client for the test server."""
    async with Client(url=_TEST_URL) as c:
        yield c


# ─────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────


async def _get_node(client: Client, *path_segments: str):
    """Resolve a browse-path relative to Objects using the test namespace."""
    ns_idx = await client.get_namespace_index(ICSGatewayOpcuaServer.NAMESPACE)
    browse_path = ["0:Objects"] + [f"{ns_idx}:{seg}" for seg in path_segments]
    return await client.nodes.root.get_child(browse_path)


# ─────────────────────────────────────────────────────────────────────
# Test 1 — Server starts without error
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_starts_without_error() -> None:
    """init() must complete without raising any exception."""
    # Arrange
    srv = ICSGatewayOpcuaServer(endpoint=_TEST_ENDPOINT)

    # Act / Assert
    try:
        await srv.init()
        assert srv._server is not None, "Server handle must be set after init()"
    finally:
        await srv.stop()


# ─────────────────────────────────────────────────────────────────────
# Test 2 — Namespace is registered
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_namespace_registered(server: ICSGatewayOpcuaServer) -> None:
    """The custom namespace index must be > 0 after init()."""
    # Assert
    assert server.namespace_index > 0, (
        f"Namespace '{ICSGatewayOpcuaServer.NAMESPACE}' was not registered "
        f"(got idx={server.namespace_index})"
    )


@pytest.mark.asyncio
async def test_namespace_matches_uri(client: Client) -> None:
    """The client must resolve our namespace URI to a valid non-zero index."""
    # Act
    idx = await client.get_namespace_index(ICSGatewayOpcuaServer.NAMESPACE)

    # Assert
    assert idx > 0, (
        f"Client could not find namespace '{ICSGatewayOpcuaServer.NAMESPACE}' "
        f"in the server's namespace table"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 3 — All expected nodes exist in the address space
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_all_water_tank_nodes_exist(client: Client) -> None:
    """Factory/WaterTank_01/{TankLevel,ValvePosition,PumpStatus} must exist."""
    # Arrange / Act
    tank_level = await _get_node(client, "Factory", "WaterTank_01", "TankLevel")
    valve_pos = await _get_node(client, "Factory", "WaterTank_01", "ValvePosition")
    pump_status = await _get_node(client, "Factory", "WaterTank_01", "PumpStatus")

    # Assert — get_child raises if node missing; just confirm handles are valid
    assert tank_level is not None, "TankLevel node missing"
    assert valve_pos is not None, "ValvePosition node missing"
    assert pump_status is not None, "PumpStatus node missing"


@pytest.mark.asyncio
async def test_all_temp_controller_nodes_exist(client: Client) -> None:
    """Factory/TempController_02/{Temperature,HeaterPower} must exist."""
    # Arrange / Act
    temperature = await _get_node(
        client, "Factory", "TempController_02", "Temperature"
    )
    heater_power = await _get_node(
        client, "Factory", "TempController_02", "HeaterPower"
    )

    # Assert
    assert temperature is not None, "Temperature node missing"
    assert heater_power is not None, "HeaterPower node missing"


# ─────────────────────────────────────────────────────────────────────
# Test 4 — TankLevel is READ-ONLY
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tank_level_is_read_only(client: Client) -> None:
    """A client write to TankLevel must be rejected with an OPC UA error."""
    # Arrange
    node = await _get_node(client, "Factory", "WaterTank_01", "TankLevel")

    # Act / Assert — any status-code error confirms the node is protected
    with pytest.raises((UaStatusCodeError, Exception)) as exc_info:
        await node.write_value(ua.DataValue(ua.Variant(99.9, ua.VariantType.Float)))

    assert exc_info.value is not None, (
        "Expected an OPC UA error when writing to read-only TankLevel node"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 5 — ValvePosition is writable
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_valve_position_is_writable(client: Client) -> None:
    """A client must be able to write to ValvePosition without error."""
    # Arrange
    node = await _get_node(client, "Factory", "WaterTank_01", "ValvePosition")

    # Act — should not raise
    await node.write_value(ua.DataValue(ua.Variant(50.0, ua.VariantType.Float)))

    # Assert — confirm write succeeded by reading back
    result = await node.read_value()
    assert result == pytest.approx(50.0), (
        f"ValvePosition should be 50.0 after write, got {result}"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 6 — PumpStatus is writable
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_pump_status_is_writable(client: Client) -> None:
    """A client must be able to write True/False to PumpStatus."""
    # Arrange
    node = await _get_node(client, "Factory", "WaterTank_01", "PumpStatus")

    # Act — write True then read back
    await node.write_value(
        ua.DataValue(ua.Variant(True, ua.VariantType.Boolean))
    )

    # Assert
    result = await node.read_value()
    assert result is True, (
        f"PumpStatus should be True after write, got {result!r}"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 7 — update_tank() pushes values into all three nodes
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_tank_changes_nodes(
    server: ICSGatewayOpcuaServer,
    client: Client,
) -> None:
    """update_tank() must update TankLevel, ValvePosition, and PumpStatus."""
    # Arrange
    expected_level: float = 73.5
    expected_valve: float = 42.0
    expected_pump: bool = True

    # Act
    await server.update_tank(
        tank_level=expected_level,
        valve_pos=expected_valve,
        pump_on=expected_pump,
    )

    # Assert
    level_node = await _get_node(client, "Factory", "WaterTank_01", "TankLevel")
    valve_node = await _get_node(client, "Factory", "WaterTank_01", "ValvePosition")
    pump_node = await _get_node(client, "Factory", "WaterTank_01", "PumpStatus")

    assert await level_node.read_value() == pytest.approx(expected_level), (
        "TankLevel not updated by update_tank()"
    )
    assert await valve_node.read_value() == pytest.approx(expected_valve), (
        "ValvePosition not updated by update_tank()"
    )
    assert await pump_node.read_value() is True, (
        "PumpStatus not updated by update_tank()"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 8 — update_temp() pushes values into Temperature and HeaterPower
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_temp_changes_nodes(
    server: ICSGatewayOpcuaServer,
    client: Client,
) -> None:
    """update_temp() must update Temperature and HeaterPower."""
    # Arrange
    expected_temp: float = 85.0
    expected_power: float = 60.0

    # Act
    await server.update_temp(temperature=expected_temp, heater_power=expected_power)

    # Assert
    temp_node = await _get_node(
        client, "Factory", "TempController_02", "Temperature"
    )
    heater_node = await _get_node(
        client, "Factory", "TempController_02", "HeaterPower"
    )

    assert await temp_node.read_value() == pytest.approx(expected_temp), (
        "Temperature not updated by update_temp()"
    )
    assert await heater_node.read_value() == pytest.approx(expected_power), (
        "HeaterPower not updated by update_temp()"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 9 — Server stops cleanly with no hanging tasks
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_stops_cleanly() -> None:
    """stop() must complete within a reasonable timeout and null the server."""
    # Arrange
    srv = ICSGatewayOpcuaServer(endpoint=_TEST_ENDPOINT)
    await srv.init()
    assert srv._server is not None, "Server must be running after init()"

    # Act — stop with a timeout guard
    await asyncio.wait_for(srv.stop(), timeout=5.0)

    # Assert
    assert srv._server is None, (
        "Server handle must be None after stop() to confirm clean shutdown"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 10 — Two concurrent reads don't block each other
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_reads_do_not_block(
    server: ICSGatewayOpcuaServer,
) -> None:
    """Two simultaneous OPC UA read tasks must both complete quickly."""
    # Arrange — seed known values
    await server.update_tank(tank_level=55.0, valve_pos=30.0, pump_on=False)

    async def read_level() -> float:
        async with Client(url=_TEST_URL) as c:
            node = await _get_node(c, "Factory", "WaterTank_01", "TankLevel")
            return await node.read_value()

    async def read_valve() -> float:
        async with Client(url=_TEST_URL) as c:
            node = await _get_node(c, "Factory", "WaterTank_01", "ValvePosition")
            return await node.read_value()

    # Act — launch both tasks concurrently with a timeout
    level, valve = await asyncio.wait_for(
        asyncio.gather(read_level(), read_valve()),
        timeout=5.0,
    )

    # Assert
    assert level == pytest.approx(55.0), (
        f"Concurrent TankLevel read returned {level}, expected 55.0"
    )
    assert valve == pytest.approx(30.0), (
        f"Concurrent ValvePosition read returned {valve}, expected 30.0"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 11 — Round-trip: server write → client read (float)
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_round_trip_tank_level(
    server: ICSGatewayOpcuaServer,
    client: Client,
) -> None:
    """Value written by update_tank() must survive unmodified to client read."""
    # Arrange
    test_value: float = 12.345

    # Act
    await server.update_tank(tank_level=test_value, valve_pos=0.0, pump_on=False)

    # Assert
    node = await _get_node(client, "Factory", "WaterTank_01", "TankLevel")
    read_back = await node.read_value()

    assert read_back == pytest.approx(test_value, abs=1e-4), (
        f"Round-trip failed: wrote {test_value}, read back {read_back}"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 12 — Round-trip: server write → client read (boolean)
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_round_trip_pump_boolean(
    server: ICSGatewayOpcuaServer,
    client: Client,
) -> None:
    """Boolean PumpStatus must round-trip correctly for both True and False."""
    # Arrange
    pump_node = await _get_node(client, "Factory", "WaterTank_01", "PumpStatus")

    for expected in (True, False):
        # Act
        await server.update_tank(tank_level=50.0, valve_pos=0.0, pump_on=expected)

        # Assert
        result = await pump_node.read_value()
        assert result is expected, (
            f"PumpStatus round-trip failed: wrote {expected}, read {result!r}"
        )


# ─────────────────────────────────────────────────────────────────────
# Test 13 — Initial node values are zero / False
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initial_values_are_zero(client: Client) -> None:
    """All nodes must report zero / False immediately after server init()."""
    # Act / Assert — WaterTank_01
    tank_level = await _get_node(client, "Factory", "WaterTank_01", "TankLevel")
    valve_pos = await _get_node(client, "Factory", "WaterTank_01", "ValvePosition")
    pump_status = await _get_node(client, "Factory", "WaterTank_01", "PumpStatus")

    assert await tank_level.read_value() == pytest.approx(0.0), (
        "TankLevel initial value must be 0.0"
    )
    assert await valve_pos.read_value() == pytest.approx(0.0), (
        "ValvePosition initial value must be 0.0"
    )
    assert await pump_status.read_value() is False, (
        "PumpStatus initial value must be False"
    )

    # Act / Assert — TempController_02
    temperature = await _get_node(
        client, "Factory", "TempController_02", "Temperature"
    )
    heater_power = await _get_node(
        client, "Factory", "TempController_02", "HeaterPower"
    )

    assert await temperature.read_value() == pytest.approx(0.0), (
        "Temperature initial value must be 0.0"
    )
    assert await heater_power.read_value() == pytest.approx(0.0), (
        "HeaterPower initial value must be 0.0"
    )


# ─────────────────────────────────────────────────────────────────────
# Test 14 — update_tank() raises if server not initialised
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_tank_before_init_raises() -> None:
    """update_tank() must raise RuntimeError if init() was never called."""
    # Arrange
    srv = ICSGatewayOpcuaServer(endpoint=_TEST_ENDPOINT)

    # Act / Assert
    with pytest.raises(RuntimeError, match="not initialised"):
        await srv.update_tank(tank_level=50.0, valve_pos=0.0, pump_on=False)


# ─────────────────────────────────────────────────────────────────────
# Test 15 — update_temp() raises if server not initialised
# ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_temp_before_init_raises() -> None:
    """update_temp() must raise RuntimeError if init() was never called."""
    # Arrange
    srv = ICSGatewayOpcuaServer(endpoint=_TEST_ENDPOINT)

    # Act / Assert
    with pytest.raises(RuntimeError, match="not initialised"):
        await srv.update_temp(temperature=25.0, heater_power=0.0)


# ─────────────────────────────────────────────────────────────────────
# Standalone runner (_PytestBridge pattern)
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import pytest

    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
