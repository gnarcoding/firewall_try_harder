## TCPDUMP COMMANDS

# Show packets with SYN flags
tcpdump -i eth0 'tcp[tcpflags] & tcp-syn != 0'

# Exclude Port 22 (SSH Traffic)
sudo tcpdump -i any tcp and not port 22 -X

# To filter traffic from a specific IP address using tcpdump
tcpdump -i any src host <specific-ip> -X

## IPTABLES COMMANDS

# Add iptables rule
iptables -A INPUT -s <ip> -j DROP

# Delete iptables rule
iptables -D INPUT -s <ip> -j DROP

# List out iptables rules
iptables -L -n -v

# Flush all iptables rules
iptables -F