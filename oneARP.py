# Python Script for detecting ARP Spoofing.
# Import
import os
import re
import time
from datetime import datetime


# Main Function
def main():
    while True:
        print()
        arp = get_arp()
        mac_list, ip_list = parse_arp(arp)
        arp_dict, keyring = find_duplicate(mac_list, ip_list)
        create_log(arp_dict, keyring)
        print("\nWaiting 10 seconds before next sweep \n Ctrl-C to Quit.")
        time.sleep(10)


# Function to receive raw ARP table.
def get_arp():
    arp = os.popen("arp -a").read()
    return arp


# Function Parses passed raw ARP table into usable MAC and IP lists
def parse_arp(arp):
    split = arp.splitlines()
    mac_list, ip_list = [], []
    mac_pattern = r'.{1,2}[:\-].{1,2}[:\-].{1,2}[:\-].{1,2}[:\-.{1,2}[:\-].{1,2}[:\-].{1,2}'
    ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    # Where the Magic Happens...
    for lines in split:
        mac = re.findall(mac_pattern, lines)
        try:
            mac = str(mac[0])
            if mac == "" or mac.startswith("ff") or mac.startswith("FF"):
                continue
            else:
                mac_list.append(mac)
        except:
            continue

        ip = re.findall(ip_pattern, lines)
        try:
            ip = str(ip[0])
            if ip != "":
                ip_list.append(ip)
        except:
            continue

    return mac_list, ip_list


# Function to create a pair of Dictionaries with matching keys
def find_duplicate(mac_list, ip_list):
    arp_dict, key_ring = {}, {}
    for i, mac in enumerate(mac_list):
        if mac in arp_dict.keys() and ip_list[i] not in arp_dict.values():
            key_ring[mac] = ip_list[i]
            print(f" Duplicate Mac Found : {mac} | {arp_dict[mac]} & {key_ring[mac]}")
            continue
        arp_dict[mac] = ip_list[i]
    return arp_dict, key_ring


# Function to create a log entry to a Date Named File. Date : MAC : IP 1 : IP 2
def create_log(arp_dict, key_ring):
    date = str(datetime.now())
    with open(f"{date[0:10]}_ARP_Log.txt", "a") as log:
        for key in key_ring:
            log.write(f"\n{date[0:19]} : \nDuplicate Mac : {key} \n   {arp_dict[key]}\n   {key_ring[key]}")


if __name__ == "__main__":
    main()
