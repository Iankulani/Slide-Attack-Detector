# -*- coding: utf-8 -*-
"""
Created on Sun Mar 2 2:38:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Slide Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time

# Dictionary to store packets and sequence numbers by IP
packet_sequence = {}

def packet_callback(packet):
    # Check if the packet has an IP layer and a TCP layer
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        seq_num = packet[scapy.TCP].seq

        # Initialize the packet sequence for the destination IP if not already present
        if dst_ip not in packet_sequence:
            packet_sequence[dst_ip] = []

        # Store the sequence number for the destination IP
        packet_sequence[dst_ip].append(seq_num)

        print(f"Received packet from {src_ip} to {dst_ip} with sequence number: {seq_num}")

def detect_slide_attack(ip_address):
    print(f"Monitoring traffic to/from {ip_address} for potential Slide Attack...")

    start_time = time.time()
    while time.time() - start_time < 60:  # Monitor for 1 minute for example
        # Look for any irregularities in the packet sequence
        if ip_address in packet_sequence:
            seq_nums = packet_sequence[ip_address]
            if len(seq_nums) > 1:
                # Sort the sequence numbers to detect irregular sliding of sequence numbers
                seq_nums.sort()

                # Check for gaps in sequence numbers (potential slide attack)
                for i in range(1, len(seq_nums)):
                    if seq_nums[i] != seq_nums[i-1] + 1:
                        print(f"Slide Attack detected! Missing packets or unexpected sequence numbers detected.")
                        print(f"Gap detected between {seq_nums[i-1]} and {seq_nums[i]}")
                        return
        time.sleep(1)

    print(f"No Slide Attack detected within the last minute of monitoring.")

def start_monitoring():
    # Prompt user to enter the IP address they want to monitor
    ip_address = input("Enter the IP address to monitor for Slide Attack: ")

    # Start sniffing packets
    print("Starting packet capture...")
    scapy.sniff(prn=packet_callback, filter=f"ip host {ip_address}", store=0, timeout=60)

    # After capturing, analyze the traffic for Slide Attack
    detect_slide_attack(ip_address)

if __name__ == "__main__":
    start_monitoring()
