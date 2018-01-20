# clear all rules
iptables -F
iptables -X
iptables -Z

#police
iptables -P INPUT DROP 
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# accept 
iptables -A INPUT -i wlp5s0 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT


# clear the nat rules 
iptables -t nat -F 
iptables -t nat -X 
iptables -t nat -Z 

# froward
echo "1" > /proc/sys/net/ipv4/ip_forward

iptables -t nat -A POSTROUTING -s 192.168.1.0/24  -o wlp5s0  -j MASQUERADE

#save 
iptables-save
