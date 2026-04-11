# RaspberryPi-ARP-Spoofer
This repo is my university production project. The project is creating an RaspberryPi that can attack a network using ARP spoofing. This repository will be contain the code of both the offense script and detection script for ARP spoofing.

### Offense
The offense folder will contain the ARP spoofing script. Inside will have a README containing instructions and explanation on how and what is an ARP spoofer.

### Defense
the *Defense* folder will contain the detection script of the ARP spoofer. Inside will contain a README that will contain instructions and explain how detection script works.

# Requirements
If you wish to recreate this project here are the requirements needed.

### Hardware

***1. Raspberry PI***
This projected uses a Raspberry PI 5 with 8gb of ram. However, you do not need the latest hardware for this. Older models of the PI should work as this project is not hardware intensive. If you don't have the money for one, an old laptop that can run Kali linux should be fine. As long as you have a device that can run Kali Linux then there should be no problem.

***2. Second Laptop/Device***
The second laptop will be acting as the victim machine as well as run the detection script. If you opt to choose a different device from a laptop so long as the device can run python as it is a needed to run the detection script. As well as being able to connect to a network.

### Software

***1. Kali Linux***

This is an all in one Pentesting Operating System. A lot of the tools needed for network hacking, port scanning, password cracking, etc. are already pre-installed and configured.

***2. Python***

You will need python so that you are able to run the scripts. This is a ***HARD*** requirement as if you cannot run or install python you will not be able to run this project.

### Python Libraries
There are only three libraries used. They are all found in the requirements.txt.

***Installation:***

First step is to set up a python virtual environment

*WINDOWS AND LINUX:*
```
python -m venv .venv
```
Then activate the venv
```
source .venv/bin/activate
```
Once the venv is activated install the requirements.txt
```
pip install -r requirements.txt
```


