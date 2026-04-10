# RaspberryPi-ARP-Spoofer
This repo is my university disertation. The project is creating an RaspberryPi that can attack a netwrok using ARP spoofing. 

### ARP Spoofing Offens

***How It Works:***
    1. The threat actor sends fake ARP responses to both vitim and router. The threat actor's MAC address pretends to be the router's IP address
    2. This then causes the victim to send traffic to the attack, as the machine thinks the attcker is the router
    3. The attacker then forwards the traffic to the router, intercepting it and then potentially manipulate the data.

***Example Scenario***
- **Victim:** Windows 11 Machine (192.168.1.xxx)
- **Attacker:** Kali Linux machine (192.168.1.xxx)
- **Router:** Default gateway (192.168.1.1)

***Steps:***
1. The victim sends and ARP request to find the MAC address of the router
2. The attecker then sends a *Fake* ARP response making the threat actor's MAC address pose as the router IP
3. The victim updates the ARP table with the threat actor's MAC address which then redirects the network traffic to the attacker not the router.

***Forwarding Traffic***
---
Due to ARP spoofing affects the LAN settings. It may DoS (Denial of Service) the victim's internet making it lose access. To prevent this you need to enable IP forwarding on th threat actor's machine. This allows attackers to pass the traffic between the victim and the router while still maintaing the internet connection as it is still intercepting traffic.
---

to enable IP forwarding on Linux:
```
echo 1 > /proc/sys/net/ipv4/ip_forward
```

***How to:***
Make to specify the correct IP addresses and network interface.

*On Linux:*
open up a terminal then type this command
```
ifconfig
```

*On Windows:*
Open up CMD or Powershell. If it doesn't work run it as administrator then try again
```
ipconfig/all
```

***Command:***
```
sudo python ARP-Spoofer.py -t <target_ip> -s <spoofed_ip> -i <interface> 
```

***Example:***
The target IP address is made up 
```
sudo ARP-Spoofer.py -t 192.168.1.122 -s 192.168.1.1 -i eth0
```
