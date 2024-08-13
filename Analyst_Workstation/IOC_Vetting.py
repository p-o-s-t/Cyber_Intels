"""
WHO MADE THIS?
    Author: post

WHAT IS THIS?
    Simple Python script to perform data enrichment on Network IOCs using external Threat Intel Platforms/Vendors

TO-DO (as of 17 DEC 2023):
    - Convert month from number of month to 3-charactor representation of month in new_file_path
    - try/catch blocks
    - create similar functions for Mandiant and Recorded Future
    - incorporate argument parsing
    - text formatting
    - Add a 0 for the dtg minutes, as it currently only returns a single digit for minutes
    - Remove hardcoded API key(s) and read keys in from a different file
    - Add a separate function for IPv6?  
"""

import requests
import json
import re
#import time # Won't be necessary if possible to get access to a non-Public API key for VirusTotal and other services
import datetime

# Get datetimegroup of analysis
dtg = datetime.datetime.utcnow()

# Grab input from user for file to be analyzed for IOCs
file_path = input("Name of file to perform analysis on: ")

# global variable for storing all IOCs
ioc_list = ''

# Open the file for reading and store into global string variable above
with open(file_path, 'r') as file:
    ioc_list = file.read().split('\n')

# File for all analysis to be written to.  Expected out: 'Vetted_IOCs_171132Z1223.docx'
# The -2000 is a placeholder for grabbing last 2 digits of current year without having to cast it to a string

new_file_path = 'Vetted_IOCs_' + str(dtg.day) + str(dtg.hour) + str(dtg.minute) + 'Z' + str(dtg.month) + str((dtg.year-2000))+'.docx'

def VirusTotalIP(ioc):
    url = "https://www.virustotal.com/api/v3/ip_addresses/" + ioc
    headers = {
        "accept": "application/json",
        "x-apikey": "<VirusTotalKey>"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_data = json.loads(response.text)
        totalScore = (json_data['data']['attributes']['last_analysis_stats']['harmless']) + (json_data['data']['attributes']['last_analysis_stats']['malicious']) + (json_data['data']['attributes']['last_analysis_stats']['suspicious']) + (json_data['data']['attributes']['last_analysis_stats']['undetected'])
        finalRating = "{}/{}".format(json_data['data']['attributes']['total_votes']['malicious'],totalScore)
        new_file.write("\t\tVirusTotal: "+finalRating+"\n")
    elif response.status_code in (400,404):
        new_file.write("\t\tVirusTotal: No record found\n")
    # time.sleep(16)

def VirusTotalDomain(ioc):
    url = "https://www.virustotal.com/api/v3/domains/" + ioc       
    headers = {
        "accept": "application/json",
        "x-apikey": "<VirusTotalKey"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_data = json.loads(response.text)
        totalScore = (json_data['data']['attributes']['last_analysis_stats']['harmless']) + (json_data['data']['attributes']['last_analysis_stats']['malicious']) + (json_data['data']['attributes']['last_analysis_stats']['suspicious']) + (json_data['data']['attributes']['last_analysis_stats']['undetected'])
        finalRating = "{}/{}".format(json_data['data']['attributes']['last_analysis_stats']['malicious'],totalScore)
        new_file.write("\t\tVirusTotal: "+finalRating+"\n")
    elif response.status_code in (400,404):
        new_file.write("\t\tVirusTotal: No record found\n") 
    #time.sleep(16)

def MandiantAnalysis(ioc):
    new_file.write("\t\tMandiant: [Placeholder]\n") 
    return

def RecordedFuture(ioc):
    new_file.write("\t\tRF: [Placeholder]\n\n") 
    return

def Fusion(ioc):
    return

with open(new_file_path, 'w') as new_file:
    for ioc in ioc_list:
        ioc = ioc.strip()
        # IPv4 address IOC
        if re.match("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", ioc):
            new_file.write("\t" + ioc +"\n")
            VirusTotalIP(ioc)
            MandiantAnalysis(ioc)
            RecordedFuture(ioc)
            #FusionAnalysis(ioc)
        # Domain IOC
        elif re.match("([a-z0-9\-]*\.)*([a-z0-9\-]*)\.[0-9a-z]{2,}",ioc):
            new_file.write("\t" + ioc +"\n")
            VirusTotalDomain(ioc)
            MandiantAnalysis(ioc)
            RecordedFuture(ioc)
            #FusionAnalysis(ioc)
        else:
            new_file.write(ioc + "\n")
