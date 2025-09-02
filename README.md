
# NetworkSniffer

<p align="center">
<a href="https://github.com/amirrezafatemi/NetworkSniffer">
    <img src="https://pngimg.com/uploads/hello/hello_PNG13.png" width="260px" alt="Open source Multi-AI Agent orchestration framework">
  </a>
</p>
<p align="center">
  <a href="https://github.com/amirrezafatemi/NetworkSniffer">
    <img src="https://img.shields.io/github/stars/amirrezafatemi/NetworkSniffer" alt="Github stars">
  </a>
  <a href="https://github.com/amirrezafatemi/NetworkSniffer/network/members">
    <img src="https://img.shields.io/github/forks/amirrezafatemi/NetworkSniffer" alt="Github forks">
  </a>
  </p>
  <p align="center">
  <a href="https://github.com/amirrezafatemi/NetworkSniffer/issues">
    <img src="https://img.shields.io/github/issues/amirrezafatemi/NetworkSniffer" alt="Github issues">
  </a>
  <a href="https://github.com/amirrezafatemi/NetworkSniffer/pulls">
    <img src="https://img.shields.io/github/issues-pr/amirrezafatemi/NetworkSniffer" alt="Github pull requests">
  </a>
  <a href="https://opensource.org/license/gpl-2-0">
    <img src="https://img.shields.io/badge/license-GPL%202.0-green" alt="License: GPL v2.0">
  </a>
</p>

### Simple and Flexible Packet Analyzer

>A simple yet handy **network packet sniffer** written in C that captures and analyzes packets traversing your network interface using [libpcap](https://www.tcpdump.org/). It allows network users learn about a specific protocol.
>If you don't know what it is [here](https://en.wikipedia.org/wiki/Packet_analyzer) is a quick reference 

## Table of contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation & Compilation](#-installation--compilation)
- [Examples](#-example)
  - [Quick Tutorial](#quick-tutorial)
- [Contribution](#-contribution)
- [License](#-license)

## 📌 Overview

**[NetworkSniffer](https://github.com/amirrezafatemi/NetworkSniffer)** listens on a network interface in **promiscuous mode** and captures raw packets directly from the network. It parses and decodes common network protocols to provide detailed insights into network traffic.

Supported protocols include:

- **Ethernet Frames** (MAC addresses, EtherType)
- **IPv4** (source/destination IPs)
- **ICMP** (echo requests/replies, type/code)
- **ARP** (Address Resolution Protocol - IP to MAC mapping)
- **TCP** (ports, sequence numbers, flags, length, decoded payload)
- **UDP** (source/destination ports, length, decoded data)

This tool is useful for network diagnostics, troubleshooting, and learning about network protocols.

## ⚙️ Features

- Capture and decode Ethernet headers
- Parse and analyze IPv4 packets
- Interpret ICMP messages (ping and error messages)
- Track ARP requests and replies
- Inspect TCP segments with detailed flag analysis and a readable payload to inspect its info
- Monitor UDP datagrams with port, length and information dedicated to that packet
- Real-time packet capturing and on-the-fly decoding
- Works on raw sockets requiring root privileges

## 🛠 Requirements

- GCC (for compiling the C source code)
- Root/administrator privileges (for raw socket access)
- **libpcap** (for packet capturing support)
- Linux operating system (tested on Debian/Ubuntu, CentOS, Fedora)

## 🚀 Installation & Compilation

### 1. Clone the repository:

```bash
   git clone https://github.com/amirrezafatemi/NetworkSniffer.git
   cd NetworkSniffer
```
### 2. Libpcap Installation

#### for Debian / Ubuntu and derivatives
   
```bash
   sudo apt update
   sudo apt install libpcap-dev
```

#### for Red Hat / CentOS / Fedora
CentOS / RHEL 7 or 8:
   
```bash
   sudo yum install libpcap-devel
```
   
Fedora (modern versions):
   
```bash
   sudo dnf install libpcap-devel
```
   
Arch Linux / Manjaro
   
```bash
   sudo pacman -S libpcap
```
   
 openSUSE
   
```bash
   sudo zypper install libpcap-devel
```
   
Alpine Linux
   
```bash
   sudo apk add libpcap-dev
```

### 3. Compile

```bash
   -gcc -o networksniffer main.c main_functions.c -l pcap
   ./networksniffer
```
   I also provided you a secondary tool named `devsfinder`.
   It simply shows all of your network interfaces.
   
   To use this tool run:
   
```bash
   gcc -o devsfinder devsfinder.c -l pcap
```

## 💡 Example
### Quick Tutorial
It's easy to use.
After the compilation, you should be able to execute the `./networksniffer` .
When the you run it, this message pops up:
```
usage: NetworkSniffer <interface>

Options:
    interface    Listen on <interface> for packets.

If you don't know your current interfaces, try running ./devsfinder   
```
If you don't know your available NIC's on your system, try `./devsfinder` .
Then after requiring your favorable  network sniffer to sniff packets, 
execute this command :
\
**NOTICE : YOU WILL NEED TO BE A SUDOER RUN IT**
```
sudo ./networksniffer <interface> (<interface> varies. it maybe 'eth0', 'wlan0', 'enp2s0 and etc )
``` 


## 🤝 Contribution
I personally believe this project hasn't reach its full potentials. In future, it's feature will expand to scan different packets' types. 
>Actually It took me long to program this much lonely, so it may also take time
>to add more features namely more and other packets' type supporting, filter feature 
>to help users see  what protocols should be captured( btw in my code, there are commented lines
>that if you use it with the correct filters defined by [libpcap filter guide](https://www.tcpdump.org/manpages/pcap-filter.7.html), it will do the filtering), saving 
>shown results to  a .cap file and etc.
>
Any contribution to this project is welcome right after your request is approved by me, Amirreza.
## 📜 License
NetworkSniffer is released under the [GNU GENERAL PUBLIC LICENSE v2.0](https://opensource.org/license/gpl-2-0).
