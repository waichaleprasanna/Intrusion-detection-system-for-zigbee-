import sqlite3
from colorama import init, Fore

init(autoreset=True)

def generate_report():
    print(Fore.CYAN + "\n=== ZIGBEE IDS: INCIDENT FORENSIC REPORT ===")
    
    conn = sqlite3.connect('zigbee_ids.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT timestamp, attack_type, source_mac, description FROM alert_history ORDER BY id ASC')
    alerts = cursor.fetchall()
    
    if not alerts:
        print(Fore.GREEN + "[+] No security incidents found in the database.")
    else:
        for alert in alerts:
            timestamp, attack, mac, details = alert
            print(Fore.RED + f"[{timestamp}] " + Fore.YELLOW + f"{attack}")
            print(Fore.WHITE + f"    Target MAC : {mac}")
            print(Fore.WHITE + f"    Details    : {details}")
            print(Fore.CYAN + "-" * 45)
            
    conn.close()
    print(Fore.GREEN + f"[+] Total incidents logged: {len(alerts)}\n")

if __name__ == "__main__":
    generate_report()
    