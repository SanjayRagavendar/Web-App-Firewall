import pyshark
from datetime import datetime

import subprocess
def get_current_time():
    current_time = datetime.now().time()
    return current_time

def block_ip(ip_address):
    # Block the IP address using iptables
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
    print(f"Blocked {ip_address}")
def append_to_log(text, log_file_path):
    try:
        with open(log_file_path, 'a') as log_file:
            log_file.write(text + '\n')
        print(f"Appended to {log_file_path}: {text}")
    except Exception as e:
        print(f"Error appending to log file {log_file_path}: {e}")



# Read IP addresses from the text file and add them to the blocklist
with open('blocklist.txt', 'r') as file:
    blocklist = set(map(str.strip, file.readlines()))

def block_packet(packet):
    if 'IP' in packet and packet.ip.src in blocklist:
        print(f"Blocked packet from {packet.ip.src}")
        block_ip(packet.ip.src)
        append_to_log(f"{packet.ip.src} is blocked at {get_current_time()}","log.txt")
        return True  # Block the packet
    else:
        return False  # Allow the packet

def packet_callback(packet):
    if not block_packet(packet):
        # Process the packet or perform further actions here
        print(f"Processing packet from {packet.ip.src}")

# Create a packet capture object on the desired interface
cap = pyshark.LiveCapture(interface='wlan0', bpf_filter='ip')

# Capture and process packets
try:
    for packet in cap.sniff_continuously(packet_count=0):
        packet_callback(packet)
except KeyboardInterrupt:
    print("Capturing stopped by user.")
