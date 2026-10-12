import time
import sqlite3
from collections import deque
from colorama import init, Fore
from scapy.all import Dot15d4, Dot15d4Data

init(autoreset=True)

# Connect to database
conn = sqlite3.connect('zigbee_ids.db')
cursor = conn.cursor()

# In-memory tracking structures
replay_cache = {}          # Key: (src_mac, seq_num) -> Value: timestamp
recent_packets = deque(maxlen=100) # Sliding window for jamming detection
AUTH_SRC = '00:12:4b:00:14:d2:6f:88'
COORD_ADDR = '00:00:00:00:00:00:00:00'

def log_alert(attack_type, src_mac, details):
    cursor.execute('''
        INSERT INTO alert_history (attack_type, source_mac, description)
        VALUES (?, ?, ?)
    ''', (attack_type, src_mac, details))
    conn.commit()

def process_frame(pkt, is_dropped=False, rssi=-50):
    """Core IDS Engine: Evaluates every frame against the 3 attack rules"""
    now = time.time()
    
    # 1. Jamming Detection Check (Sliding window packet loss / RSSI)
    recent_packets.append(1 if is_dropped else 0)
    if len(recent_packets) >= 10:
        loss_rate = (sum(recent_packets) / len(recent_packets)) * 100
        if loss_rate > 50 or rssi < -85:
            print(Fore.RED + f"[!] CRITICAL ALERT: Jamming / DoS Detected! Packet Loss: {loss_rate:.1f}%, RSSI: {rssi} dBm")
            log_alert('Jamming Attack', 'Airwave/RF', f'Packet loss {loss_rate:.1f}%')
            return

    if is_dropped or not pkt.haslayer(Dot15d4):
        return

    seq = pkt[Dot15d4].seqnum
    src_mac = getattr(pkt[Dot15d4Data], 'src_addr', 'Unknown') if pkt.haslayer(Dot15d4Data) else 'Unknown'

    # 2. Rogue Device Detection Check (Whitelist validation)
    cursor.execute('SELECT * FROM device_registry WHERE mac_address = ?', (src_mac,))
    if not cursor.fetchone():
        print(Fore.MAGENTA + f"[!] ALERT: Rogue Device Infiltration Detected! Unauthorized MAC: {src_mac}")
        log_alert('Rogue Device', src_mac, 'Device not in authorized whitelist')
        return

    # 3. Replay Attack Detection Check (Duplicate seq within 60s)
    cache_key = (src_mac, seq)
    if cache_key in replay_cache and (now - replay_cache[cache_key]) <= 60:
        print(Fore.RED + f"[!] ALERT: Replay Attack Detected! Duplicate Seq: {seq} from {src_mac}")
        log_alert('Replay Attack', src_mac, f'Duplicate sequence number {seq}')
        return

    replay_cache[cache_key] = now
    print(Fore.GREEN + f"[+] Normal Frame Processed | Src: {src_mac} | Seq: {seq} | RSSI: {rssi} dBm")

def run_attack_simulation():
    print(Fore.CYAN + "=== STARTING ZIGBEE IDS SIMULATION RUN ===\n")
    
    # Stage 1: Legitimate Baseline Traffic
    print(Fore.YELLOW + "[Scenario 1] Processing legitimate telemetry from whitelisted sensor...")
    for seq in range(1, 4):
        frame = Dot15d4(seqnum=seq) / Dot15d4Data(src_addr=AUTH_SRC, dest_addr=COORD_ADDR)
        process_frame(frame, is_dropped=False, rssi=-55)
        time.sleep(0.8)

    # Stage 2: Replay Attack Simulation
    print(Fore.YELLOW + "\n[Scenario 2] Attacker capturing and replaying valid packet Seq #2...")
    time.sleep(1)
    replayed_frame = Dot15d4(seqnum=2) / Dot15d4Data(src_addr=AUTH_SRC, dest_addr=COORD_ADDR)
    process_frame(replayed_frame, is_dropped=False, rssi=-55)
    time.sleep(1)

    # Stage 3: Rogue Device Infiltration Simulation
    print(Fore.YELLOW + "\n[Scenario 3] Unauthorized rogue device transmitting packets...")
    time.sleep(1)
    rogue_frame = Dot15d4(seqnum=1) / Dot15d4Data(src_addr='aa:bb:cc:dd:ee:ff:00:11', dest_addr=COORD_ADDR)
    process_frame(rogue_frame, is_dropped=False, rssi=-60)
    time.sleep(1)

    # Stage 4: Channel Jamming (DoS) Simulation
    print(Fore.YELLOW + "\n[Scenario 4] Attacker flooding 2.4 GHz channel (simulating RF noise)...")
    time.sleep(1)
    for _ in range(12):
        process_frame(None, is_dropped=True, rssi=-95)
        time.sleep(0.2)

    print(Fore.CYAN + "\n=== SIMULATION COMPLETED: All alerts successfully stored in SQLite! ===")

if __name__ == "__main__":
    run_attack_simulation()
    