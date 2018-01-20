# clear all rules
iptables -F
iptables -X
iptables -Z

#police
iptables -P INPUT ACCEPT 
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -t nat -X 
iptables -t nat -Z 

#save 
iptables-save
