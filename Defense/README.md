# ARP Detection Script

### How It Works:
***PASSIVE***
1. Checks know traffic for any inconsistencies between IP and MAC pairs
2. If found consistent it will drop that packet then move on to the next
3. Once found inconsistent it will alarm the user that it they are under attack

***ACTIVE***

Within the time of this research I had time to add active detection:
1. ARP message reply answer will be checked if it is real through sending a
TCP SYN packet
2. If the TCP SYN is receives a TCP ACK reply then the IP and MAC pair will be added
to the IP and MAC pair table
3. However, if the TCP ACK is not received then warn the user they are under attack

***Example Scenario***
- **Victim:** Windows 11 Machine (192.168.1.xxx)
- **Attacker:** Kali Linux Machine (192.168.1.xxx)

***Steps:***
1. Attacker attempts to ARP spoof the victim machine
2. Victim machine runs detection script to check ARP requests
3. Script checks incoming ARP messages for any inconsistencies, if found then
the script will alarm the victim that they are under attack

***How To:***

On Linux:

```
sudo python ARP-Detection.py 
```

On Windows:

If the script doesn't run you may need to open powershell as an administrator
```
python .\ARP-Detection.py
```
