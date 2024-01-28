import requests
import time

# Define the URL of your Flask application
url = 'http://localhost:5000/'

# Send requests to the Flask application
for _ in range(10):
    response = requests.get(url)
    print(response.text)

# Simulate requests from different IP addresses
for _ in range(10):
    response = requests.get(url, headers={'X-Forwarded-For': '192.168.1.1'})
    print(response.text)



