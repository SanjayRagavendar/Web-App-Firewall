import pyshark
import subprocess

def block_ip(ip_address):
    # Block the IP address using iptables
    subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
    print(f"Blocked {ip_address}")
# Define the blocklist of IP addresses
blocklist = {"192.168.1.1", "10.0.0.2","127.0.0.1","216.239.38.120","172.31.98.147","192.168.34.152"}  # Add the IP addresses you want to block

def block_packet(packet):
    if 'IP' in packet and packet.ip.src in blocklist:
        print(f"Blocked packet from {packet.ip.src}")
        block_ip(packet.ip.src)
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
