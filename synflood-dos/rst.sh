iptables -F
iptables -X 
iptables -Z
iptables -A OUTPUT  -p tcp --tcp-flags RST RST  -j DROP
