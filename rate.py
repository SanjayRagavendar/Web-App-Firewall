import pyshark
import time

# Dictionary to store last access time for each IP address
ip_access_times = {}

# Rate limit settings
max_requests_per_second = 5

def process_packet(packet):
    try:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst

        # Check if the IP address is in the dictionary
        if ip_src in ip_access_times:
            # Check if the time since the last access is within the rate limit
            if time.time() - ip_access_times[ip_src] < 1 / max_requests_per_second:
                print(f"Rate limit exceeded for {ip_src}")
                return

        # Update the last access time for the IP address
        ip_access_times[ip_src] = time.time()

        # Process the packet (you can add your logic here)
        print(f"Packet received from {ip_src} to {ip_dst}")

    except AttributeError:
        # Handle packets without IP layer (e.g., non-IP packets)
        pass

def main():
    # Use the default network interface (you may need to adjust this based on your setup)
    capture = pyshark.LiveCapture(interface='wlan0')

    for packet in capture.sniff_continuously():
        process_packet(packet)

if __name__ == "__main__":
    main()
