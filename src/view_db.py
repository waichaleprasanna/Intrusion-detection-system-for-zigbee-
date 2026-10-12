import sqlite3

conn = sqlite3.connect('zigbee_ids.db')
cursor = conn.cursor()

print("=== DEVICE REGISTRY (Whitelist) ===")
cursor.execute("SELECT * FROM device_registry")
for row in cursor.fetchall():
    print(row)

print("\n=== PACKET LOGS ===")
cursor.execute("SELECT * FROM packet_logs LIMIT 5")
for row in cursor.fetchall():
    print(row)

print("\n=== ALERT HISTORY ===")
cursor.execute("SELECT * FROM alert_history")
for row in cursor.fetchall():
    print(row)

conn.close()