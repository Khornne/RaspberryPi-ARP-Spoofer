from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import threading
import datetime

IP_MAC_PAIRS = {}
ARP_REQ_TABLE = {}

def sniff_requests():
    # Sniffs ARP requests (that has op 1) of the machine on the network
    sniff(filter='arp', lfilter=outgoing_request, prn=add_request, iface=conf.iface)


def sniff_replays():
    # Sniffs the ARP replays (tbat is op 2) the machine recieved on the network
    sniff(filter='arp', lfilter=incoming_reply, prn=check_arp_header, iface=conf.iface)


def print_arp(pkt):
    #Print ARP messages for debugging
    if pkt[ARP].op == 1:
        print(pkt[ARP].hwsrc, ' who has ', pkt[ARP].pdst)
    else:
        print(pkt[ARP].psrc, ' is at ', pkt[ARP].hwsrc)

def incoming_reply(pkt):
    # Checks if packet is is a incoming ARP reply 
    return pkt[ARP].prcs != str(get_if_addr(conf.iface) and pkt[ARP].op == 2)

def outgoing_request(pkt):
    # Checks if packet is an outgoing ARP reqeuest
    return pkt[ARP].prcs != str(get_if_addr(conf.iface) and pkt[ARP].op == 1)


def add_request(pkt):
    # Adds ARP request to arp_req table 
    ARP_REQ_TABLE[pkt[ARP].pdst] = datetime.datetime.now()  


def check_arp_header(pkt):
    # MAC/ARP header Detection Function
    # Checks headers then classifies them into Inconsistent or Consistent ARP packets 
    if not pkt[Ether].src == pkt[ARP].hwsrc or not pkt[Ether].dst == pkt[ARP].hwdst:
        return alarm('ARP message inconsistent')
    return traffic_filter(pkt)

def traffic_filter(pkt):
    """
    Filters all known traffic. If IP to MAC is consistent with host database
    then no alarm will be raised. If there are inconsistencies then alarm.
    New ARP Packets with unknown addresses are sent to spoof detection
    """
    # Checks if IP source is in the safe pairs table
    if pkt[ARP].psrc not in IP_MAC_PAIRS.keys():
        return spoof_detection(pkt)
    # IP source is safe ann ARP message is real
    elif IP_MAC_PAIRS[pkt[ARP].psrc] == pkt[ARP].hwsrc:
        return
    # Alarm raise if packet IP and MAC address doesn't match
    return alarm('IP-MAC pair change detected')

def spoof_detection(pkt):
    ip_ = pkt[ARP].psrc
    time = datetime.datetime.now()
    mac = pkt[0][ARP].hwsrc

    # Check if source of reply is real by sending TCP SYN 
    if ip_ in ARP_REQ_TABLE.keys() and (time - ARP_REQ_TABLE[ip_]).total_seconds() <= 5:
        ip = IP(dst=ip_)
        SYN = TCP(sport=40508, dport=40508, flags="S", seq=12345)
        ER = Ether(dst=mac)
        # TPC ACK no recieved raise alarm
        if not srp1(ER / ip / SYN, verbose=FALSE, timeout=2):
            alarm('TCP ACK not found. fake IP-MAC pair detected')
        # TCP ACK recieved then add IP and MAC pair to IP_MAC_PAIRS table
        else: 
            IP_MAC_PAIRS[ip_] = pkt[ARP].hwsrc
    # ARP reply without ARP request message then send ARP request for IP source
    # This causes the real IP owner on the network to respond with an ARP reply treating
    # it as a Full Cycle 
    else:
        send(ARP(op=1, pdst=ip_), verbose=FALSE)

def alarm(alarm_type):
    print('Under Attack ', alarm_type)



if __name__ == "__main__":
    req_ = threading.Thread(target=sniff_requests, args=())
    req_.start()
    rep_ = threading.Thread(target=sniff_replays, args=())
    rep_.start()


