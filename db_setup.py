import sqlite3

def setup_database():
    # This creates a local file named 'zigbee_ids.db' in your folder
    conn = sqlite3.connect('zigbee_ids.db')
    cursor = conn.cursor()

    # 1. Packet Logs: To store historical traffic
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_mac TEXT,
            dest_mac TEXT,
            sequence_num INTEGER,
            raw_sequence_num INTEGER,
            rssi INTEGER
        )
    ''')

    # 2. Alert History: To log confirmed attacks
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            attack_type TEXT,
            source_mac TEXT,
            description TEXT
        )
    ''')

    # 3. Device Registry: The authorized MAC whitelist for Rogue Device detection
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_registry (
            mac_address TEXT PRIMARY KEY,
            device_type TEXT,
            date_added DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()
    print("Database and tables successfully created!")

if __name__ == "__main__":
    setup_database()