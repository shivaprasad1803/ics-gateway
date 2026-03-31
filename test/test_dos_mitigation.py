import time
import logging
from pymodbus.client import ModbusTcpClient

# Configure logging to see the connection details
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

def test_dos_throttling(host='localhost', port=5020, rate_limit=10):
    """
    Simulates a flood attack to verify the A06 Rate Throttling logic.
    Target: PLC_01 Valve Position (HR 1)
    """
    client = ModbusTcpClient(host, port=port)
    
    if not client.connect():
        log.error("Could not connect to PhysicsGuard server. Is it running?")
        return

    print(f"--- Starting DoS Verification (Limit: {rate_limit} cmd/s) ---")
    
    success_count = 0
    blocked_count = 0
    total_attempts = 25  # We send more than double the limit
    
    start_time = time.monotonic()

    for i in range(total_attempts):
        # Sending commands as fast as the loop allows
        # Alternating values slightly to avoid triggering R008 ReplayRule
        val = 20 + (i % 5)
        response = client.write_register(1, val)        
        if response.isError():
            # In a real DoS block, the server might close the connection 
            # or return a Modbus exception.
            blocked_count += 1
        else:
            success_count += 1
            
        if i == rate_limit - 1:
            log.info(f"Sent {rate_limit} commands. Next commands should be throttled...")

    duration = time.monotonic() - start_time
    client.close()

    print("\n--- Test Results ---")
    print(f"Total Attempts : {total_attempts}")
    print(f"Allowed (Sent) : {success_count}")
    print(f"Blocked/Dropped: {blocked_count}")
    print(f"Test Duration  : {duration:.2f} seconds")

    # Validation Logic
    if success_count <= rate_limit + 1: # Allowing a small buffer for timing
        print("\n✅ SUCCESS: DoS Protection is ACTIVE. Excessive commands were throttled.")
    else:
        print("\n❌ FAILURE: Server accepted too many commands. Check the _is_rate_limited logic.")

if __name__ == "__main__":
    test_dos_throttling()
