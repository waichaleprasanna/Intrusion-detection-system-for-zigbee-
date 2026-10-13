# Zigbee IDS

A Windows prototype intrusion detection system for **Zigbee / Zigbee2MQTT** activity. A detection engine watches device traffic, stores events in SQLite and shows live packets and alerts on a Flask + Socket.IO dashboard. Local attack-simulation tools let you demonstrate the detections without attacking anything real.

> Final-year project, Dept. of Electronics & Communication Engineering, Dr. Ambedkar Institute of Technology, Bengaluru. Guide: Dr. B. Sivakumar.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![Flask](https://img.shields.io/badge/Flask-Socket.IO-lightgrey) ![SQLite](https://img.shields.io/badge/SQLite-storage-003B57) ![Platform](https://img.shields.io/badge/Platform-Windows-0078D6)

<!-- Add screenshots to screenshots/dashboard and uncomment
![Dashboard](screenshots/dashboard/dashboard.png) -->

## Features
- Live packet and alert feed over Socket.IO
- SQLite history of packets, devices and alerts
- Detections: **replay**, **rogue device**, **sensor-reset burst**, **packet flood**
- Optional live sensor readings from Zigbee2MQTT over MQTT
- Local UDP attack simulation (`attack_tool.py`, `simulate_attacks.py`)
- CC2531 sniffer support for Wireshark captures

> Detection logic is experimental and has not been benchmarked.

## How it fits together
```
Zigbee sensor ─► ZBDongle-E + Zigbee2MQTT ─► MQTT ─┐
Attack simulators (local UDP) ─────────────────────┼─► Detection engine ─► SQLite ─► Flask + Socket.IO dashboard
CC2531 sniffer ─► Wireshark (analysis)             ┘
```

## Repository layout
```
├── src/
│   ├── app.py               Flask + Socket.IO dashboard
│   ├── engine.py            detection engine
│   ├── sniffer.py           packet capture
│   ├── attack_tool.py       interactive localhost attack simulator
│   ├── simulate_attacks.py  additional attack simulation
│   ├── db_setup.py          create the database
│   ├── seed_db.py           seed the authorized sensor
│   ├── seed_whitelist.py    seed the device whitelist
│   ├── view_db.py           inspect stored data
│   ├── view_alerts.py       list alerts
│   └── templates/           dashboard HTML
├── scripts/                 start_dashboard.ps1, start_engine_sim.bat
├── firmware/                sniffer and coordinator firmware notes
├── setup/                   hardware, Zigbee2MQTT, Wireshark, software
├── attacks/                 attack write-ups
├── docs/  results/  screenshots/
├── requirements.txt  requirements-mqtt.txt
└── LICENSE
```

## Requirements and setup
Windows 10/11, Python 3.10+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src\db_setup.py

$env:ZIGBEE_AUTH_SENSOR_MAC = "0x..."   # your authorized sensor's address
python src\seed_db.py
```

For live Zigbee2MQTT readings:
```powershell
python -m pip install -r requirements-mqtt.txt
```

| Variable | Purpose | Default |
|---|---|---|
| `ZIGBEE_AUTH_SENSOR_MAC` | Authorized device used when seeding | none |
| `Z2M_MQTT_HOST` / `Z2M_MQTT_PORT` | MQTT broker | `127.0.0.1` / `1883` |
| `Z2M_BASE_TOPIC` | Zigbee2MQTT base topic | `zigbee2mqtt` |
| `Z2M_DEVICE` | Device filter (empty = all) | `temp_sensor-1` |
| `Z2M_MQTT_USERNAME` / `Z2M_MQTT_PASSWORD` | Broker login | none |
| `FLASK_SECRET_KEY` | Flask secret; set a unique random value | none |

## Run
Start the dashboard first (port 5000), then the engine and simulation:
```powershell
.\scripts\start_dashboard.ps1
.\scripts\start_engine_sim.bat
```
Open http://127.0.0.1:5000.

## Hardware used
- Sonoff ZBDongle-E coordinator (Zigbee2MQTT 2.14.1, Mosquitto, channel 15)
- Sonoff SNZB-02D temperature/humidity sensor (`temp_sensor-1`)
- CC2531 USB dongles as sniffers, flashed with a CC Debugger
- Wireshark with the TI Packet Converter

Firmware notes: [firmware/](firmware/). Setup guides: [setup/](setup/).

## Safety and troubleshooting
- The database holds MAC addresses and alert data. Do not publish `.db` files.
- The dashboard binds to all interfaces and accepts cross-origin Socket.IO clients. Restrict access outside a trusted local lab.
- Set `FLASK_SECRET_KEY` to a unique value.
- Attack tools are for **your own test setup only**.

## Roadmap
- [ ] Benchmark script to measure detection accuracy
- [ ] ZCL temperature/humidity payload analysis
- [ ] Device topology view

## Author
**Prasanna**, final-year ECE student, Bengaluru. [GitHub](https://github.com/waichaleprasanna)

## License
MIT. See [LICENSE](LICENSE).
