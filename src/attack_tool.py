import time
import socket
from colorama import init, Fore
from scapy.all import Dot15d4, Dot15d4Data, conf

init(autoreset=True)
conf.dot15d4_protocol = 'zigbee'

# Configuration matching your live network
COORD_ADDR = 0x0000                    # Coordinator Address
ROGUE_MAC = 0xa1b2c3d4e5f60011         # Unregistered Rogue Device MAC

# UDP virtual channel bridge for standalone attack transmission
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
TARGET_HOST = ('127.0.0.1', 9999)
CONTROL_HOST = ('127.0.0.1', 9998)
SIM_REPLAY_PREFIX = b'SIM_REPLAY:'
SIM_FLOOD_PREFIX = b'SIM_FLOOD:'
SIM_ROGUE_PREFIX = b'SIM_ROGUE:'
TEST_PAN_ID = 0x1A62

def make_test_data_frame(seqnum, src_addr):
    # Scapy defaults to a Beacon with no source address mode; explicitly build
    # a parseable MAC Data frame so the IDS can inspect the simulated source.
    src_mode = 3 if src_addr > 0xffff else 2  # Long EUI-64 or short 16-bit address
    mac_header = Dot15d4(
        fcf_frametype=1, fcf_srcaddrmode=src_mode, fcf_destaddrmode=2,
        fcf_panidcompress=0, seqnum=seqnum & 0xff
    )
    data_header = Dot15d4Data(
        dest_panid=TEST_PAN_ID, dest_addr=COORD_ADDR,
        src_panid=TEST_PAN_ID, src_addr=src_addr
    )
    return mac_header / data_header

def get_newest_authorized_frame():
    last_error = None
    for attempt in range(5):
        control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        control_sock.settimeout(1)
        try:
            control_sock.sendto(b'GET_LATEST', CONTROL_HOST)
            raw_frame, _ = control_sock.recvfrom(2048)
            break
        except (OSError, socket.timeout) as e:
            last_error = e
            raw_frame = b''
            if attempt < 4:
                time.sleep(0.25)
        finally:
            control_sock.close()
    else:
        raise RuntimeError('Cannot reach the IDS frame service at 127.0.0.1:9998. Start engine.py in another terminal with ENABLE_UDP_ATTACK_STREAM=1, and confirm it prints that the UDP test stream is enabled.') from last_error

    if not raw_frame:
        raise RuntimeError('No recent authorized frame is cached. Wait for live sensor traffic and try again.')
    frame = Dot15d4(raw_frame)
    if not frame.haslayer(Dot15d4Data):
        raise RuntimeError('The newest authorized frame is not a data frame that this simulator can replay.')
    return raw_frame, frame
def trigger_replay_attack():
    print(Fore.YELLOW + "\n[*] Replaying the newest authorized frame seen by the IDS...")
    try:
        raw_frame, frame = get_newest_authorized_frame()
    except (OSError, RuntimeError) as e:
        print(Fore.RED + f"[-] Replay test unavailable: {e}\n")
        return

    seq = getattr(frame[Dot15d4], 'seqnum', '?')
    src = getattr(frame[Dot15d4Data], 'src_addr', 'Unknown')
    print(Fore.CYAN + f"    Captured frame: source={src}, sequence={seq}, bytes={len(raw_frame)}")
    print(Fore.YELLOW + f"    [REINJECTED FRAME] source={src}, sequence={seq}")
    time.sleep(0.2)  # Let the IDS cache the original before replaying it.
    sock.sendto(SIM_REPLAY_PREFIX + raw_frame, TARGET_HOST)
    print(Fore.GREEN + "[+] Tagged reinjection sent to the local IDS over 127.0.0.1.\n")
def trigger_rogue_device_attack():
    print(Fore.MAGENTA + "\n[*] Executing Rogue Device Attack...")
    print(Fore.CYAN + f"    Injecting association/data frame from unauthorized MAC: {hex(ROGUE_MAC)}...")
    rogue_frame = make_test_data_frame(1, ROGUE_MAC)
    sock.sendto(SIM_ROGUE_PREFIX + bytes(rogue_frame), TARGET_HOST)
    print(Fore.GREEN + "[+] Unauthorized device packet transmitted.\n")

def trigger_jamming_attack():
    print(Fore.RED + "\n[*] Executing sustained local packet-flood detector test...")
    print(Fore.CYAN + "    Sending test frames to the local IDS for about 3 seconds over 127.0.0.1...")
    for i in range(120):
        dummy_frame = make_test_data_frame(i, 0xffff)
        sock.sendto(SIM_FLOOD_PREFIX + bytes(dummy_frame), TARGET_HOST)
        time.sleep(0.025)
    print(Fore.GREEN + "[+] Local packet-flood detector test complete. No radio transmission was used.\n")

def attack_menu():
    while True:
        print(Fore.CYAN + "========================================")
        print(Fore.CYAN + "   LOCAL ZIGBEE IDS TEST SIMULATOR      ")
        print(Fore.CYAN + "========================================")
        print("1. Simulate Replay (duplicate sequence over localhost)")
        print("2. Simulate Rogue Device (unwhitelisted MAC over localhost)")
        print("3. Simulate Sustained Packet Flood (localhost)")
        print("4. Exit")
        choice = input("\nSelect an attack option (1-4): ").strip()
        
        if choice == '1':
            trigger_replay_attack()
        elif choice == '2':
            trigger_rogue_device_attack()
        elif choice == '3':
            trigger_jamming_attack()
        elif choice == '4':
            break

if __name__ == "__main__":
    attack_menu()
