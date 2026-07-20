#!/bin/bash
# Watch Man IDRS Auto-Generated Block Rules

iptables -A INPUT -s 10.0.0.5 -j DROP # Blocked Port Scan
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 192.168.1.150 -j DROP # Blocked DoS
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 192.168.1.150 -j DROP # Blocked DoS
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 192.168.1.150 -j DROP # Blocked DoS
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 192.168.1.150 -j DROP # Blocked DoS
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 10.0.0.50 -j DROP # Blocked SYN Flood
iptables -A INPUT -s 192.168.1.150 -j DROP # Blocked DoS
iptables -A INPUT -s 172.16.0.50 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 91.108.4.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 172.16.0.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 8.8.8.8 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 45.33.32.156 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 185.220.101.5 -j DROP # Blocked DoS
iptables -A INPUT -s 192.168.1.30 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 1.1.1.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.0.0.5 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.20 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 104.21.32.100 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.10 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 208.67.222.222 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.0.0.10 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.100 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.30 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 8.8.8.8 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.0.0.10 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 185.220.101.5 -j DROP # Blocked DoS
iptables -A INPUT -s 172.16.0.50 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 208.67.222.222 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.100 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 172.16.0.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.20 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 91.108.4.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 45.33.32.156 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 1.1.1.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 192.168.1.10 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.0.0.5 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 104.21.32.100 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.238.74.185 -j DROP # Blocked DoS
iptables -A INPUT -s 10.37.237.185 -j DROP # Blocked DoS
iptables -A INPUT -s 10.113.135.185 -j DROP # Blocked DoS
iptables -A INPUT -s 192.168.1.202 -j DROP # Blocked DoS
iptables -A INPUT -s 218.248.112.65 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 218.248.112.1 -j DROP # Blocked DNS Attack
iptables -A INPUT -s 10.238.74.185 -j DROP # Blocked DoS
iptables -A INPUT -s 10.238.74.185 -j DROP # Blocked DoS
