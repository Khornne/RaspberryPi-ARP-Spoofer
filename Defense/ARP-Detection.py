from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}

def sniff_requests():
    # Sniffs ARP requests (that has op 1) of the machine on the network
    sniff(filter='arp', lfilter=outgoing_req, orn=add_req, iface=conf.iface)


def sniff_replays():
    # Sniffs the ARP replays (tbat is op 2) the machine recieved on the network
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface=conf.iface)


def print_arp(pkt):
    #Print ARP messages for debugging
    if pkt[ARP].op == 1:
        print(pkt[ARP].hwsrc, ' who has ', pkt[ARP].pdst)
    else:
        print(pkt[ARP].psrc, ' is at ', pkt[ARP].hwsrc)

