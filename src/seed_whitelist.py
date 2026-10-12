import os
import sqlite3

REAL_SENSOR_MAC = os.environ.get('ZIGBEE_AUTH_SENSOR_MAC')
if not REAL_SENSOR_MAC:
    raise SystemExit('Set ZIGBEE_AUTH_SENSOR_MAC to your authorized device address before seeding the registry.')

# Your exact SONOFF sensor MAC address


conn = sqlite3.connect('zigbee_ids.db')
cursor = conn.cursor()

cursor.execute('''
    INSERT OR REPLACE INTO device_registry (mac_address, device_type)
    VALUES (?, ?)
''', (REAL_SENSOR_MAC, 'SONOFF SNZB-02D Temperature Sensor'))

conn.commit()

# Verify the record
cursor.execute('SELECT * FROM device_registry')
print("Current Whitelisted Devices:")
for row in cursor.fetchall():
    print(f"  MAC: {row[0]} | Type: {row[1]}")

conn.close()
