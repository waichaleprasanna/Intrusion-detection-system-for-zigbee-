import sqlite3
import time
from colorama import init, Fore
from scapy.all import PcapReader, Dot15d4, Dot15d4Data

# Initialize colorama for colored terminal output
init(autoreset=True)

# Connect to the SQLite database
conn = sqlite3.connect('zigbee_ids.db', check_same_thread=False)
cursor = conn.cursor()

def log_packet_to_db(src_mac, dest_mac, seq_num, rssi):
    """Logs the extracted packet data into the SQLite database."""
    try:
        cursor.execute('''
            INSERT INTO packet_logs (source_mac, dest_mac, sequence_num, rssi)
            VALUES (?, ?, ?, ?)
        ''', (src_mac, dest_mac, seq_num, rssi))
        conn.commit()
    except Exception as e:
        print(Fore.RED + f"[-] Database Error: {e}")

def process_packet(packet):
    """Parses the raw packet and extracts critical security fields."""
    # Check if the packet contains the 802.15.4 MAC layer
    if packet.haslayer(Dot15d4):
        seq_num = packet[Dot15d4].seqnum
        
        # Default placeholders if addresses or RSSI are missing in the frame
        src_mac = "Unknown"
        dest_mac = "Unknown"
        rssi = -50 # Simulated RSSI for now
        
        # Extract MAC addresses if it is a Data frame
        if packet.haslayer(Dot15d4Data):
            src_mac = getattr(packet[Dot15d4Data], 'src_addr', 'Unknown')
            dest_mac = getattr(packet[Dot15d4Data], 'dest_addr', 'Unknown')

        # Format and print the captured data to the terminal
        print(Fore.GREEN + f"[+] Packet Captured!")
        print(Fore.WHITE + f"    Source MAC : {src_mac}")
        print(Fore.WHITE + f"    Dest MAC   : {dest_mac}")
        print(Fore.WHITE + f"    Seq Number : {seq_num}")
        print(Fore.WHITE + "-" * 40)
        
        # Save to database for the detection engine to analyze
        log_packet_to_db(str(src_mac), str(dest_mac), seq_num, rssi)

def start_intelligent_sniffer(pipe_path):
    print(Fore.CYAN + f"[*] Connecting to database and TiWsPc pipe at {pipe_path}...")
    
    try:
        # Scapy's PcapReader can natively read the PCAP stream from the Windows pipe
        with PcapReader(pipe_path) as pcap_reader:
            print(Fore.GREEN + "[+] Engine active! Listening for Zigbee frames...\n")
            
            for packet in pcap_reader:
                process_packet(packet)
                
    except FileNotFoundError:
        print(Fore.RED + f"[-] Error: Could not find the pipe {pipe_path}.")
        print(Fore.RED + "Make sure TiWsPc is running and broadcasting.")
    except KeyboardInterrupt:
        print(Fore.RED + "\n[-] Sniffer safely stopped by user.")
    finally:
        conn.close()

if __name__ == "__main__":
    TARGET_PIPE = r'\\.\pipe\tiwspc_data'
    start_intelligent_sniffer(TARGET_PIPE)