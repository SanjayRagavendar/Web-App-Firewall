from flask import request, abort
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",  # Use in-memory storage for simplicity (not suitable for production)
    application_limits=["5 per minute", "1 per second"],
)

blocked_ip={}
i=0
def block_checker():
    if i==100:
        i=0
        remove_old_entries()
    client_ip = request.remote_addr

    # Check if the client's IP is in the blacklist
    if client_ip in blocked_ip:
        with open("./logs/log.txt",'a') as f:
            f.write(datetime.now(),client_ip,request+'\n\n')
        abort(403)

def add_block(ip):

# Get the current time
    current_time = datetime.now()

# Add 10 minutes to the current time
    new_time = current_time + timedelta(minutes=10)
    blocked_ip[ip]=new_time

def del_block(ip):
    del blocked_ip[ip]

def check_rate_limit(request):
    # Rate limit check
    if limiter.is_rate_limited(request.remote_addr):
        return True  # IP is rate-limited
    return False

def remove_old_entries():
    current_time = datetime.now()
    threshold = timedelta(minutes=10)

    # List to store keys to be removed
    keys_to_remove = []

    for ip, end_time in blocked_ip.items():
        # Check if the difference between the current time and creation time exceeds the threshold
        if current_time >=end_time:
            keys_to_remove.append(ip)

    # Remove the entries corresponding to the expired IPs
    for key in keys_to_remove:
        blocked_ip.pop(key, None)

