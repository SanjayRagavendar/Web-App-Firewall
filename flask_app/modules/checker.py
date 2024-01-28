from flask import request, abort
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",  # Use in-memory storage for simplicity (not suitable for production)
    application_limits=["5 per minute", "1 per second"],
)

blocked_ip={}

i=0
def block_checker(request):
    global i
    if i==100:
        i=0
        remove_old_entries()
    client_ip = request.remote_addr
    i+=1
    
    # Check if the client's IP is in the blacklist
    with open("modules/blocklist.txt","r") as r:
        for blocked_ip in r:
            if client_ip == blocked_ip.split(':')[0]:
                with open("../logs/log.txt",'a') as f:
                    f.write(f"{datetime.now()} {client_ip} {str(request)} Blocked Request\n")
                return 1
    return 0

def add_block(ip):

# Get the current time
    current_time = datetime.now()

# Add 10 minutes to the current time
    end_time = current_time + timedelta(minutes=10)
    print(f"{ip} has been added to the blacklist till {end_time}")
    with open("flask_app/modules/blocklist.txt","a") as f:
        f.write(f"{ip}:{end_time}")

def del_block(ip):
    with open("flask_app/modules/blocklist.txt", 'r') as file:
        lines = file.readlines()

    # Filter out the entry to remove
    new_lines = [line.strip() for line in lines if line.split(":")[0]!=ip]

    # Rewrite the modified contents back to the file
    with open("flask_app/modules/blocklist.txt", 'w') as file:
        for line in new_lines:
            file.write(line + '\n')
    print(f"{ip} has be removed from the blacklist")

def check_rate_limit(request):
    if limiter.is_rate_limited(request.remote_addr):
        with open("../logs/log.txt","a") as f:
            f.write(f"{datetime.now()} {request.remote_addr} {str(request)} Rate Limiting IP Blocked\n")
        add_block(request.remote_addr)


def remove_old_entries():
    current_time = datetime.now()
    # List to store keys to be removed
    keys_to_remove = []

    for ip, end_time in blocked_ip.items():
        # Check if the difference between the current time and creation time exceeds the threshold
        if current_time >=end_time:
            keys_to_remove.append(ip)

    # Remove the entries corresponding to the expired IPs
    for key in keys_to_remove:
        blocked_ip.pop(key, None)
    
    print("Old Enteries are removed from the blocklist")

def req_limit_min(limit_per_minute):
    limiter._storage_connection_kwargs = {"application_limits": [f"{limit_per_minute} per minute"]}
    print(f"Limited update to {limit_per_minute} Limit per minute")

def req_limit_sec(limit_per_second):
    limiter._storage_connection_kwargs = {"application_limits": [ f"{limit_per_second} per second"]}
    print(f"Limit updated to {limit_per_second} per second")