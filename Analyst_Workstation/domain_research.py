#! /usr/bin/python3

import requests
import json
from datetime import date
import os
from security import safe_requests

""" 
TO-DO:
    - Better way to pass only the  apex domain to Security Trails
    - Put API Keys for sites in a seperate file
    - Call other python programs to scan the sites?
    - Prettify output into a PDF or other doc
    - Performance speed
    - Options, argument parsing
    - Profit
"""

ASCII_LOGO = r"""
__________         .____________              
\____    /____   __| _/   _____/ ____   ____  
  /     // __ \ / __ |\_____  \_/ __ \_/ ___\ 
 /     /\  ___// /_/ |/        \  ___/\  \___ 
/_______ \___  >____ /_______  /\___  >\___  >
        \/   \/     \/       \/     \/     \/ 

Domain Research"""

print(ASCII_LOGO)

endpoint = input("\nWhat domain would you like to scan? ")

if "http" in endpoint:
    domain = endpoint.lstrip("http://")
    domain = domain.rstrip("/")
elif "https" in endpoint:
    domain = endpoint.lstrip("https://")
    domain = domain.rstrip("/")
else:
    domain = endpoint.rstrip("/")
    
print("Scanning", endpoint+ "...")

def jprint(obj):
    # create a formatted string of the Python JSON Object
    text = json.dumps(obj, sort_keys=True, indent=4)
    return text

filename = domain + '-' + date.today().isoformat() 

with open(filename, 'w') as f:
    # Get submission info from URLScan
    f.write("[-----------------URLScan.io------------------]\n")
    headers = {'API-Key':'<URLScanKey>','Content-Type':'application/json'}
    data = {"url": endpoint, "visibility": "unlisted"}
    response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
    f.write(jprint(response.json()))


    # Get Historical information from Security Trails
    f.write("\n\n[--------------Security Trails----------------]\n")
    url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    headers = {"accept": "application/json","APIKEY": "<SecurityTrailsKey>"}
    response = safe_requests.get(url, headers=headers)
    f.write(jprint(response.json()))

    # Get information from Virus Total
    f.write("\n\n[----------------Virus Total------------------]\n")
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/votes"
    headers = {"accept":"application/json","x-apikey": "<VirusTotalKey>"}
    response = safe_requests.get(url, headers=headers)
    f.write(jprint(response.json()))

# open the file for you
os.system(f'open {filename}')
