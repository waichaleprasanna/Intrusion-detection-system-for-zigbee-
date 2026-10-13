import json
import os
import sqlite3
import threading
import time
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'dev-only-change-me')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
latest_sensor_readings = {}
detection_enabled = True


@socketio.on('connect')
def send_cached_sensor_readings():
    emit('detection_mode_changed', {'enabled': detection_enabled})
    for reading in latest_sensor_readings.values():
        emit('new_sensor_reading', reading)


@socketio.on('set_detection_mode')
def set_detection_mode(data):
    global detection_enabled
    enabled = data.get('enabled') if isinstance(data, dict) else None
    if not isinstance(enabled, bool):
        return
    detection_enabled = enabled
    socketio.emit('detection_mode_changed', {'enabled': detection_enabled})



def mqtt_sensor_worker():
    """Forward decoded Zigbee2MQTT sensor states to connected dashboard clients."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        print("[!] MQTT sensor display unavailable: install paho-mqtt from requirements-mqtt.txt")
        return

    host = os.environ.get('Z2M_MQTT_HOST', '127.0.0.1')
    port = int(os.environ.get('Z2M_MQTT_PORT', '1883'))
    base_topic = os.environ.get('Z2M_BASE_TOPIC', 'zigbee2mqtt').strip('/')
    wanted_device = os.environ.get('Z2M_DEVICE', '').strip()
    username = os.environ.get('Z2M_MQTT_USERNAME')
    password = os.environ.get('Z2M_MQTT_PASSWORD')
    topic_prefix = base_topic + '/'

    while True:
        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=f'zigbee-ids-dashboard-{os.getpid()}'
        )
        if username:
            client.username_pw_set(username, password)

        def on_connect(client, userdata, flags, reason_code, properties):
            if reason_code == 0:
                client.subscribe(topic_prefix + '#')
                print(f"[+] Subscribed to Zigbee2MQTT sensor topics at {host}:{port}/{topic_prefix}#")
            else:
                print(f"[!] MQTT connection refused: {reason_code}")

        def on_message(client, userdata, message):
            if not message.topic.startswith(topic_prefix):
                return
            device_name = message.topic[len(topic_prefix):]
            if not device_name or '/' in device_name:
                return
            if wanted_device and device_name != wanted_device:
                return
            try:
                state = json.loads(message.payload.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return
            if not isinstance(state, dict) or not any(k in state for k in ('temperature', 'humidity')):
                return
            reading = {
                'friendly_name': device_name,
                'temperature': state.get('temperature'),
                'humidity': state.get('humidity'),
                'battery': state.get('battery'),
                'voltage': state.get('voltage'),
                'updated_at': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            latest_sensor_readings[device_name] = reading
            socketio.emit('new_sensor_reading', reading)

        client.on_connect = on_connect
        client.on_message = on_message
        try:
            client.connect(host, port, keepalive=60)
            client.loop_forever()
        except Exception as exc:
            print(f"[!] Zigbee2MQTT MQTT connection unavailable: {exc}")
            time.sleep(5)
        finally:
            try:
                client.disconnect()
            except Exception:
                pass


def start_mqtt_sensor_worker():
    thread = threading.Thread(target=mqtt_sensor_worker, daemon=True)
    thread.start()

def get_db():
    conn = sqlite3.connect('zigbee_ids.db')
    conn.row_factory = sqlite3.Row
    return conn

def ensure_sequence_schema(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(packet_logs)").fetchall()}
    if "raw_sequence_num" not in columns:
        conn.execute("ALTER TABLE packet_logs ADD COLUMN raw_sequence_num INTEGER")
    conn.execute("UPDATE packet_logs SET raw_sequence_num = sequence_num WHERE raw_sequence_num IS NULL")
    conn.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    conn = get_db()
    ensure_sequence_schema(conn)
    total_packets = conn.execute('SELECT COUNT(*) FROM packet_logs').fetchone()[0]
    total_alerts = conn.execute('SELECT COUNT(*) FROM alert_history').fetchone()[0]
    devices = conn.execute('SELECT COUNT(*) FROM device_registry').fetchone()[0]

    recent_pkts = conn.execute('SELECT source_mac, sequence_num, raw_sequence_num, rssi FROM packet_logs ORDER BY id DESC LIMIT 25').fetchall()
    recent_alrts = conn.execute('SELECT attack_type, source_mac, description FROM alert_history ORDER BY id DESC LIMIT 25').fetchall()
    conn.close()

    return jsonify({
        'total_packets': total_packets,
        'total_alerts': total_alerts,
        'devices': devices,
        'recent_packets': [dict(ix) for ix in reversed(recent_pkts)],
        'recent_alerts': [dict(ix) for ix in reversed(recent_alrts)]
    })

@socketio.on('forward_packet')
def forward_packet(data):
    socketio.emit('new_packet', data)

@socketio.on('forward_alert')
def forward_alert(data):
    socketio.emit('new_alert', data)

if __name__ == '__main__':
    start_mqtt_sensor_worker()
    print("[*] Dashboard active on port 5000")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
