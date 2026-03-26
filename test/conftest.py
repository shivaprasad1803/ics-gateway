"""
conftest.py  —  Shared Test Fixtures
=====================================
PhysicsGuard ICS Security Gateway
Test infrastructure for Layer 1 and beyond.

Provides:
  fresh_tank     : WaterTankController at default initial state
  live_client    : connected pymodbus client (requires server on :5020)
  controlled_tank: WaterTankController with custom initial level (factory)

NOTE: Unit tests (test_water_tank.py) use only fresh_tank — no server needed.
      Integration tests (test_attack_scenarios.py) require the server running.
"""

import time
import threading
import pytest

from src.water_tank import WaterTankController


@pytest.fixture
def fresh_tank() -> WaterTankController:
    """
    Return a WaterTankController at default initial state.
    No server required. Safe for pure unit tests.
    """
    return WaterTankController()


@pytest.fixture
def high_tank() -> WaterTankController:
    """
    Return a WaterTankController with tank at 80% (above dry-run threshold).
    Useful for testing pump-start scenarios.
    """
    tank = WaterTankController(INITIAL_LEVEL=80.0)
    return tank


@pytest.fixture
def low_tank() -> WaterTankController:
    """
    Return a WaterTankController with tank at 5% (below dry-run threshold).
    Useful for testing pump interlock.
    """
    tank = WaterTankController(INITIAL_LEVEL=5.0)
    return tank
