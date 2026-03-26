"""
test_db_verify.py  —  Quick DB verification script
===================================================
Run this AFTER running test_attack_scenarios.py with the server up.
Queries logs/physicsguard.db and prints what was logged.

Usage:
  Terminal 1: python src/modbus_server.py
  Terminal 2: python tests/test_attack_scenarios.py
  Terminal 2: python tests/test_db_verify.py
"""

import os
import sys
import sqlite3
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def main():
    db_path = "logs/physicsguard.db"

    if not os.path.exists(db_path):
        print(f"❌ DB not found at {db_path}")
        print("   Start the server first: python src/modbus_server.py")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    print()
    print("=" * 62)
    print("  PhysicsGuard  |  Forensic DB Verification")
    print(f"  DB: {db_path}")
    print("=" * 62)

    # Total counts
    cur = conn.execute("SELECT COUNT(*), SUM(allowed=0), SUM(allowed=1) FROM commands")
    row = cur.fetchone()
    total, blocked, allowed = row[0] or 0, row[1] or 0, row[2] or 0
    print(f"\n  Total commands : {total}")
    print(f"  Blocked        : {blocked}")
    print(f"  Allowed        : {allowed}")
    if total:
        print(f"  Block rate     : {blocked/total*100:.1f}%")

    if total == 0:
        print()
        print("  ⚠️  No records yet.")
        print("  Make sure the server is running and run:")
        print("     python tests/test_attack_scenarios.py")
        print("  Then wait 2 seconds and re-run this script.")
        conn.close()
        return

    # By MITRE tag
    print("\n  By MITRE tag (blocked only):")
    cur = conn.execute(
        "SELECT mitre_tag, COUNT(*) FROM commands WHERE allowed=0 AND mitre_tag!='' "
        "GROUP BY mitre_tag ORDER BY 2 DESC"
    )
    for row in cur.fetchall():
        print(f"    {row[0]:<10} {row[1]} attacks")

    # By rule
    print("\n  By rule ID (blocked only):")
    cur = conn.execute(
        "SELECT rule_id, COUNT(*) FROM commands WHERE allowed=0 AND rule_id!='' "
        "GROUP BY rule_id ORDER BY 2 DESC"
    )
    for row in cur.fetchall():
        print(f"    {row[0]:<8} {row[1]} blocks")

    # Last 10 blocked
    print("\n  Last 10 blocked commands:")
    print(f"  {'rule_id':<8} {'severity':<12} {'mitre':<8} {'reg':<5} {'value':<8} source_ip")
    print(f"  {'-'*8} {'-'*12} {'-'*8} {'-'*5} {'-'*8} {'-'*12}")
    cur = conn.execute(
        "SELECT rule_id, severity, mitre_tag, address, value, source_ip "
        "FROM commands WHERE allowed=0 ORDER BY timestamp DESC LIMIT 10"
    )
    for row in cur.fetchall():
        print(f"  {row[0]:<8} {row[1]:<12} {row[2]:<8} {row[3]:<5} {row[4]:<8.1f} {row[5]}")

    print()
    print("=" * 62)
    conn.close()


if __name__ == "__main__":
    main()
