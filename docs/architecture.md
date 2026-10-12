# Architecture

## Components

- Dashboard (app.py) serves templates/index.html, reads SQLite statistics, and relays live events over Socket.IO.
- Detection engine (engine.py) consumes Zigbee frames, stores records, evaluates detection conditions, and forwards updates. A localhost UDP test feed is available when explicitly enabled.
- Capture (sniffer.py) reads PCAP-formatted frames from the configured Windows named pipe and writes parsed fields to SQLite.
- MQTT subscriber (app.py) listens to Zigbee2MQTT state topics and forwards sensor readings. It does not publish commands.
- Simulation tools (attack_tool.py and simulate_attacks.py) generate lab test traffic.
- SQLite (zigbee_ids.db) stores packet logs, alert history, and authorized devices. This is local generated state, not source material.

## Data flow

    Zigbee capture or local simulator -> engine/sniffer -> SQLite -> Socket.IO -> dashboard
    Zigbee2MQTT broker -> MQTT state topics -> dashboard

Scripts expect to run from the repository directory and use a relative database path. Keeping them at the root preserves current launch behavior.

## Trust boundaries

The dashboard binds to all network interfaces and currently allows cross-origin Socket.IO clients. Restrict access and review those settings before exposing it beyond a trusted lab. Keep broker credentials and FLASK_SECRET_KEY in local environment variables. Never commit databases or captures.
