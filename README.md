<<<<<<< HEAD
# Zigbee IDS Dashboard

A Windows-based prototype for monitoring Zigbee and Zigbee2MQTT activity. It combines a Flask Socket.IO dashboard, SQLite event store, IDS engine, and local attack simulation tools.

> Research and lab prototype. Validate detection behavior before relying on alerts. The attack simulator uses localhost UDP and does not transmit over Zigbee radio.

## Features

- Live packet and alert updates through Socket.IO.
- SQLite history for packets, alerts, and registered devices.
- Replay, rogue-device, sensor-reset burst, and packet-flood checks.
- Optional Zigbee2MQTT sensor readings over MQTT.
- Local UDP simulation and Windows named-pipe capture support.

## Repository layout

Runtime scripts stay at the root because they use root-relative database paths and current launch scripts.

    zigbee/
    ├── app.py                 Dashboard and MQTT subscriber
    ├── engine.py              IDS processing and dashboard forwarding
    ├── db_setup.py            Create SQLite schema
    ├── seed_db.py             Add authorized sensor to registry
    ├── sniffer.py             Read capture frames from Windows named pipe
    ├── attack_tool.py         Interactive localhost simulator
    ├── simulate_attacks.py    Additional simulation utility
    ├── view_alerts.py         Print stored alerts
    ├── view_db.py             Inspect local database
    ├── templates/index.html   Dashboard page
    ├── docs/architecture.md  Components and data flow
    ├── requirements.txt       Core dependencies
    └── requirements-mqtt.txt  Optional MQTT client

Local databases, backups, packet captures, logs, Python caches, and environment files are excluded from version control.

## Requirements and setup

Windows 10/11 is needed for the supplied launch scripts and named-pipe capture. Use Python 3.10 or newer. From PowerShell in the project directory:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt
    python db_setup.py

This creates an empty database only if one does not already exist. If you already use the dashboard, preserve your existing zigbee_ids.db; do not reset it. Before seeding, set ZIGBEE_AUTH_SENSOR_MAC to your authorized device address in the local PowerShell session, then run python seed_db.py. For example: $env:ZIGBEE_AUTH_SENSOR_MAC = "0x...". The helper has no default device identifier; keep personal identifiers private.

## Run

Start the dashboard in one window with .\start_dashboard.ps1. Install optional MQTT support using python -m pip install -r requirements-mqtt.txt. In a second window, run .\start_engine_sim.bat. That launcher enables the localhost UDP simulation feed. The dashboard listens on port 5000. Physical capture also requires compatible hardware and the configured Windows capture bridge.

The supplied dashboard launcher uses broker 127.0.0.1:1883, topic base zigbee2mqtt, and friendly name temp_sensor-1. Override with environment variables Z2M_MQTT_HOST, Z2M_MQTT_PORT, Z2M_BASE_TOPIC, Z2M_DEVICE, Z2M_MQTT_USERNAME, and Z2M_MQTT_PASSWORD. Leave Z2M_DEVICE empty to accept every device state topic. The subscriber listens to state topics and does not publish commands.

Set FLASK_SECRET_KEY to a unique random value before use beyond a trusted local lab. Keep MQTT credentials and secret values in the local environment, never committed files.

## Safety and troubleshooting

The database can contain MAC addresses, packet history, and alert descriptions; keep it private. The dashboard binds to all network interfaces and currently allows cross-origin Socket.IO clients. Restrict network access before sharing it beyond a trusted lab. Use simulations only on systems you own or are authorized to test. This prototype's alerts are experimental, not a guarantee of detection.

If the database is missing, start from the project folder and run db_setup.py only when creating a fresh database. If MQTT readings are missing, install requirements-mqtt.txt and verify the broker and device filter. Start the dashboard before the engine and verify port 5000. For capture issues, check the Windows bridge, named pipe, hardware, and permissions.

## License

No license has been selected. Add one before inviting reuse or redistribution.



=======
# Intrusion-detection-system-for-zigbee
A low-cost, real-time Intrusion Detection System (IDS) for Zigbee smart home and IoT networks. Uses a CC2531 USB dongle in promiscuous mode with a Python-based analysis engine to detect Replay, Jamming, and Rogue Device attacks.
>>>>>>> 61f56b17555fdfe3182832a7ed6ab966c7b0726b
