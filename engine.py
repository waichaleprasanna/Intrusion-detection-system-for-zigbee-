import time
import os
import socket
import sqlite3
import threading
from collections import defaultdict, deque
from colorama import init, Fore
from scapy.all import Dot15d4, Dot15d4Data, conf
import socketio
import win32file

init(autoreset=True)
conf.dot15d4_protocol = 'zigbee'

# Optional simulated/test packet feed. Disabled unless explicitly enabled.
ENABLE_UDP_ATTACK_STREAM = os.environ.get('ENABLE_UDP_ATTACK_STREAM', '').strip() == '1'

# Keep the newest authorized frame for an explicit localhost replay test.
latest_frame = None
latest_frame_seen_at = 0.0
latest_frame_info = None
latest_frame_lock = threading.Lock()

# Detection starts enabled; the dashboard toggle controls alert generation.
IDS_DETECTION_ENABLED = True

# 1. Connect to Web Dashboard WebSocket
sio = socketio.Client()

@sio.on('detection_mode_changed')
def on_detection_mode_changed(data):
    global IDS_DETECTION_ENABLED
    IDS_DETECTION_ENABLED = bool(data.get('enabled', True))
    state = 'ON' if IDS_DETECTION_ENABLED else 'OFF'
    print(Fore.CYAN + f"[*] IDS detection {state} (dashboard control)")

def connect_socket():
    try:
        sio.connect('http://127.0.0.1:5000')
        print(Fore.GREEN + "[+] Connected to Web Dashboard WebSocket!")
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not connect to Web Dashboard: {e}")

connect_socket()

# 2. Database Connection
conn = sqlite3.connect('zigbee_ids.db', check_same_thread=False)
cursor = conn.cursor()

def ensure_sequence_schema():
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(packet_logs)").fetchall()}
    if "raw_sequence_num" not in columns:
        cursor.execute("ALTER TABLE packet_logs ADD COLUMN raw_sequence_num INTEGER")
    cursor.execute("UPDATE packet_logs SET raw_sequence_num = sequence_num WHERE raw_sequence_num IS NULL")
    conn.commit()

ensure_sequence_schema()

replay_cache = {}
sequence_state = {}
RESET_MONITOR_ADDRESS = os.environ.get('ZIGBEE_RESET_MONITOR_ADDRESS', '0x9d89').strip().lower()
RESET_BURST_COUNT = int(os.environ.get('ZIGBEE_RESET_BURST_COUNT', '5'))
RESET_BURST_WINDOW_SECONDS = float(os.environ.get('ZIGBEE_RESET_BURST_WINDOW_SECONDS', '10'))
RESET_ALERT_COOLDOWN_SECONDS = float(os.environ.get('ZIGBEE_RESET_ALERT_COOLDOWN_SECONDS', '30'))
FLOOD_RATE_WINDOW_SECONDS = float(os.environ.get('ZIGBEE_FLOOD_WINDOW_SECONDS', '3'))
FLOOD_MIN_PACKETS = int(os.environ.get('ZIGBEE_FLOOD_MIN_PACKETS', '90'))
FLOOD_MIN_DURATION_SECONDS = float(os.environ.get('ZIGBEE_FLOOD_MIN_DURATION_SECONDS', '2.5'))
FLOOD_ALERT_COOLDOWN_SECONDS = float(os.environ.get('ZIGBEE_FLOOD_ALERT_COOLDOWN_SECONDS', '30'))
sensor_activity_windows = defaultdict(lambda: deque(maxlen=RESET_BURST_COUNT))
sensor_alerted_at = {}
packet_rate_windows = defaultdict(lambda: deque(maxlen=1000))
flood_alerted_at = {}

def get_display_sequence(src_addr, wire_seq):
    wire_seq = int(wire_seq) & 0xff
    state = sequence_state.get(src_addr)
    if state is None:
        cursor.execute(
            'SELECT sequence_num, raw_sequence_num FROM packet_logs WHERE source_mac = ? ORDER BY id DESC LIMIT 1',
            (src_addr,)
        )
        previous = cursor.fetchone()
        if previous is None:
            display_seq = wire_seq
            sequence_state[src_addr] = (wire_seq, display_seq)
            return display_seq
        previous_display = int(previous[0])
        previous_wire = int(previous[1]) & 0xff
    else:
        previous_wire, previous_display = state

    delta = wire_seq - previous_wire
    if delta < -128:
        delta += 256
    elif delta > 128:
        delta -= 256
    display_seq = previous_display + delta
    sequence_state[src_addr] = (wire_seq, display_seq)
    return display_seq

def emit_packet_event(data):
    if sio.connected:
        try:
            sio.emit('forward_packet', data)
        except Exception:
            pass

def log_alert(attack_type, mac, details):
    if not IDS_DETECTION_ENABLED:
        return
    cursor.execute('INSERT INTO alert_history (attack_type, source_mac, description) VALUES (?, ?, ?)', 
                   (attack_type, str(mac), details))
    conn.commit()
    if sio.connected:
        try:
            sio.emit('forward_alert', {'type': attack_type, 'src': str(mac), 'desc': details})
        except Exception:
            pass

def process_packet(packet, raw_frame=None, simulated_replay=False, simulated_flood=False, simulated_rogue=False):
    now = time.time()

    if not packet.haslayer(Dot15d4):
        return

    seq = getattr(packet[Dot15d4], 'seqnum', 0)
    src_addr = "Unknown"

    # Extract source address across all 802.15.4 frame types
    if packet.haslayer(Dot15d4Data) and hasattr(packet[Dot15d4Data], 'src_addr') and packet[Dot15d4Data].src_addr is not None:
        src_addr = hex(packet[Dot15d4Data].src_addr)
    elif hasattr(packet[Dot15d4], 'src_addr') and packet[Dot15d4].src_addr is not None:
        src_addr = hex(packet[Dot15d4].src_addr)
    else:
        # Fallback to direct field check for command frames
        for f in ['src_addr', 'source', 'src']:
            if hasattr(packet, f) and getattr(packet, f) is not None:
                src_addr = hex(getattr(packet, f))
                break

    if src_addr in ["Unknown", "0x0", "None"]:
        return

    # Monitor repeated traffic from the configured temperature sensor.
    if IDS_DETECTION_ENABLED and src_addr == RESET_MONITOR_ADDRESS:
        activity = sensor_activity_windows[src_addr]
        activity.append(now)
        while activity and now - activity[0] > RESET_BURST_WINDOW_SECONDS:
            activity.popleft()
        if (len(activity) >= RESET_BURST_COUNT and
                now - sensor_alerted_at.get(src_addr, 0.0) >= RESET_ALERT_COOLDOWN_SECONDS):
            details = (f"{len(activity)} frames within {RESET_BURST_WINDOW_SECONDS:g}s; "
                       "possible repeated button wake/rejoin activity")
            print(Fore.YELLOW + f"[SENSOR RESET/WAKE BURST] {src_addr}: {details}")
            log_alert('Sensor Reset/Wake Burst', src_addr, details)
            sensor_alerted_at[src_addr] = now

    packet_flood_detected = False

    # Require a sustained per-source burst to avoid alerting on brief sensor bursts.
    # Decoded frame rate can indicate a packet flood, but cannot confirm RF jamming.
    if IDS_DETECTION_ENABLED and src_addr != RESET_MONITOR_ADDRESS:
        rate_window = packet_rate_windows[src_addr]
        rate_window.append(now)
        while rate_window and now - rate_window[0] > FLOOD_RATE_WINDOW_SECONDS:
            rate_window.popleft()
        sustained_for = now - rate_window[0] if rate_window else 0.0
        if (len(rate_window) >= FLOOD_MIN_PACKETS and
                sustained_for >= FLOOD_MIN_DURATION_SECONDS):
            if now - flood_alerted_at.get(src_addr, 0.0) >= FLOOD_ALERT_COOLDOWN_SECONDS:
                details = (
                    f'SUSTAINED PACKET FLOOD: {len(rate_window)} decoded frames from this source '
                    f'within {FLOOD_RATE_WINDOW_SECONDS:g}s, sustained for {sustained_for:.1f}s. '
                    'This is a decoded traffic-rate anomaly, not confirmation of RF jamming.'
                )
                print(Fore.RED + f"[!] SUSTAINED PACKET FLOOD: {src_addr} | {details}")
                log_alert('Sustained Packet Flood', src_addr, details)
                flood_alerted_at[src_addr] = now
                packet_flood_detected = True
            rate_window.clear()

    # Check for short retries (< 0.15s MAC layer retry filter). Local replay
    # tests are surfaced even if they arrive within the retry interval.
    if (src_addr, seq) in replay_cache:
        delta = now - replay_cache[(src_addr, seq)]
        if delta <= 0.15 and not simulated_replay:
            return
        elif delta <= 60:
            if simulated_replay:
                display_seq = sequence_state.get(src_addr, (seq, seq))[1]
                emit_packet_event({
                    'kind': 'replay_injected', 'tag': 'REINJECTED COPY',
                    'src': src_addr, 'seq': seq, 'display_seq': display_seq, 'rssi': -50
                })
                print(Fore.YELLOW + f"[SIMULATED REINJECTION] Src {src_addr} | Seq {seq}")
                if IDS_DETECTION_ENABLED:
                    log_alert('Replay Attack', src_addr, f'SIMULATED REINJECTION over localhost: duplicate sequence {seq}')
            elif IDS_DETECTION_ENABLED:
                print(Fore.RED + f"[!] ALERT: Replay Attack! Duplicate Seq: {seq} from {src_addr}")
                log_alert('Replay Attack', src_addr, f'Duplicate sequence: {seq}')
            return

    # Rogue device verification for 64-bit IEEE addresses
    if IDS_DETECTION_ENABLED and len(src_addr) > 8:
        cursor.execute('SELECT * FROM device_registry WHERE mac_address = ?', (src_addr,))
        if not cursor.fetchone():
            display_seq = get_display_sequence(src_addr, seq)
            emit_packet_event({
                'kind': 'rogue_device', 'tag': 'ROGUE DEVICE DETECTED',
                'src': src_addr, 'seq': seq, 'display_seq': display_seq, 'rssi': -50
            })
            print(Fore.MAGENTA + f"[!] ALERT: Rogue Device! Unauthorized: {src_addr}")
            log_alert('Rogue Device', src_addr, 'MAC address not found in whitelist')
            return

    # Keep live sequence tracking separate from localhost attack-test frames.
    if simulated_flood or simulated_rogue:
        display_seq = seq
    else:
        display_seq = get_display_sequence(src_addr, seq)

    # Cache only live data frames as the authorized source for replay tests.
    if packet.haslayer(Dot15d4Data) and not (simulated_flood or simulated_rogue):
        frame_bytes = raw_frame if raw_frame is not None else bytes(packet)
        with latest_frame_lock:
            global latest_frame, latest_frame_seen_at, latest_frame_info
            latest_frame = frame_bytes
            latest_frame_seen_at = now
            latest_frame_info = {
                'src': src_addr, 'seq': seq, 'display_seq': display_seq, 'rssi': -50
            }

    # Surface local attack tests in the feed without counting them as captured air traffic.
    if not (simulated_flood or simulated_rogue):
        replay_cache[(src_addr, seq)] = now
        cursor.execute('INSERT INTO packet_logs (source_mac, sequence_num, raw_sequence_num, rssi) VALUES (?, ?, ?, ?)',
                       (src_addr, display_seq, seq, -50))
        conn.commit()
        print(Fore.GREEN + f"[+] Normal Traffic -> Src: {src_addr} | Seq: {display_seq} (wire: {seq})")

    if packet_flood_detected:
        event = {'kind': 'packet_flood', 'tag': 'PACKET FLOOD DETECTED'}
    elif simulated_flood:
        event = {'kind': 'simulated_flood', 'tag': 'FLOOD TEST FRAME'}
    elif simulated_rogue:
        event = {'kind': 'simulated_rogue', 'tag': 'ROGUE DEVICE TEST (IDS OFF)'}
    else:
        event = {}
    emit_packet_event({
        **event, 'src': src_addr, 'seq': seq, 'display_seq': display_seq, 'rssi': -50
    })

# Background listener for attack_tool.py UDP stream
def udp_attack_listener():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', 9999))
    while True:
        try:
            data, _ = udp_sock.recvfrom(2048)
            replay_prefix = b'SIM_REPLAY:'
            flood_prefix = b'SIM_FLOOD:'
            rogue_prefix = b'SIM_ROGUE:'
            simulated_replay = data.startswith(replay_prefix)
            simulated_flood = data.startswith(flood_prefix)
            simulated_rogue = data.startswith(rogue_prefix)
            if simulated_replay:
                data = data[len(replay_prefix):]
            elif simulated_flood:
                data = data[len(flood_prefix):]
            elif simulated_rogue:
                data = data[len(rogue_prefix):]
            pkt = Dot15d4(data)
            process_packet(
                pkt, simulated_replay=simulated_replay,
                simulated_flood=simulated_flood, simulated_rogue=simulated_rogue
            )
        except Exception:
            continue

# Local-only control endpoint used to fetch the newest authorized frame for a replay test.
def udp_latest_frame_listener():
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(('127.0.0.1', 9998))
    while True:
        try:
            request, client = udp_sock.recvfrom(64)
            if request != b'GET_LATEST':
                continue
            with latest_frame_lock:
                frame = latest_frame
                seen_at = latest_frame_seen_at
            if seen_at == 0.0 or time.time() - seen_at > 60:
                frame = None
            udp_sock.sendto(frame if frame is not None else b'', client)
        except Exception:
            continue

# Live TiWsPc named pipe reader
def run_live_pipe():
    if ENABLE_UDP_ATTACK_STREAM:
        t = threading.Thread(target=udp_attack_listener, daemon=True)
        t.start()
        latest_thread = threading.Thread(target=udp_latest_frame_listener, daemon=True)
        latest_thread.start()
        print(Fore.YELLOW + "[*] UDP test stream enabled on 127.0.0.1:9999; latest-frame control on 127.0.0.1:9998")
    else:
        print(Fore.CYAN + "[*] UDP test stream disabled (set ENABLE_UDP_ATTACK_STREAM=1 to enable)")

    pipe_path = r'\\.\pipe\tiwspc_data'
    print(Fore.CYAN + f"[*] Connecting to live sniffer stream on {pipe_path}...")
    try:
        handle = win32file.CreateFile(
            pipe_path, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None
        )
        print(Fore.GREEN + "[+] IDS Engine Connected to Pipe! Forwarding packets to Dashboard...\n")
        
        # Read PCAP Global Header (24 bytes)
        _ = win32file.ReadFile(handle, 24)
        
        while True:
            hr, hdr = win32file.ReadFile(handle, 16)
            if not hdr or len(hdr) < 16:
                break
            incl_len = int.from_bytes(hdr[8:12], byteorder='little')
            hr, raw_pkt = win32file.ReadFile(handle, incl_len)
            process_packet(Dot15d4(raw_pkt), raw_pkt)
    except Exception as e:
        print(Fore.RED + f"[-] Pipe connection error: {e}")
        print(Fore.YELLOW + "[*] Keep TiWsPc running and ensure no other process is reading the pipe.")
        while True:
            time.sleep(1)

if __name__ == "__main__":
    run_live_pipe()