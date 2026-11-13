#!/bin/bash

# ==========================================
# AcmeCorp Tufin Jumpbox Hardening Script
# ==========================================

echo "Starting firewall hardening..."

# 1. Flush all existing rules to start fresh
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# 2. Set Default Policies (Drop inbound, allow outbound)
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 3. Allow local loopback traffic (important for the server to talk to itself)
iptables -A INPUT -i lo -j ACCEPT

# 4. Allow return traffic for connections the server started (Stateful)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 5. Allow SSH (Port 22) ONLY from a specific Admin IP
# NOTE: You will change "10.0.0.99" to your Docker container's IP during testing
ADMIN_IP="10.0.0.99"
iptables -A INPUT -p tcp --dport 22 -s $ADMIN_IP -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 172.16.50.0/24 -j ACCEPT

# 6. Allow HTTPS (Port 443) from anywhere
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# 7. Log dropped packets (Rate limited so it doesn't crash the server)
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4

echo "Hardening complete."