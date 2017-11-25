import socket
from until import str2hex,ethernet
from proto import Packet

sniffer = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
sniffer.bind(('wlp5s0',0))
while True:
    packet = sniffer.recvfrom(65565)
    header = packet[0]
    try:
        # ethernet(str2hex(header))
        p = Packet(str2hex(header))
        p.summary()
    except Exception as e:
        print(e)
    tail = list(packet[1])
    tail[4] = str2hex(tail[4])
    # print (str2hex(header))
    # print(tail)
    # break
