from scapy.all import sniff, TCP, IP
from collections import defaultdict
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

# Dictionary to store connection attempts
connection_tracker = defaultdict(set)

# Detection thresholds
THRESHOLD = 10  # Number of different ports probed from same IP
TIME_WINDOW = 60  # Time window in seconds (not implemented in this basic version)

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags

        # Check for SYN-only packets (typical of scans)
        if flags == "S":
            connection_tracker[ip_src].add(dst_port)

            if len(connection_tracker[ip_src]) > THRESHOLD:
                print(
                    f"{Fore.RED}[ALERT]{Style.RESET_ALL} {ip_src} is scanning ports on {ip_dst} | Ports: {len(connection_tracker[ip_src])} | Time: {datetime.now().strftime('%H:%M:%S')}"
                )

def main():
    print(f"{Fore.CYAN}[*] Mini-NIDS is running... Press Ctrl+C to stop.{Style.RESET_ALL}")
    sniff(filter="tcp", prn=detect_port_scan, store=0)

if __name__ == "__main__":
    main()
