# Software setup

- Python 3.9+
- `pip install -r requirements.txt` (Flask)
- `pip install -r requirements-mqtt.txt` only for the Zigbee2MQTT integration
- Create the database: `python src/db_setup.py`, then `python src/seed_whitelist.py`
- Run: `python src/app.py`
