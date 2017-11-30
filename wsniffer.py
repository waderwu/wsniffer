import socket
import traceback
import netifaces
from util import str2hex
from proto import Packet

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

ifaces = netifaces.interfaces()
def sniff(ifrace='wlp3s0'):
    sniffer.bind((ifrace, 0))
    while True:
        packet = sniffer.recvfrom(65565)
        header = packet[0]
        try:
            p = Packet(str2hex(header))
            p.summary()
            if p.tcp:
                if not p.stream_index:
                    print(p.stream_index)
                    print(p.tcp.source_port)
                    print(p.tcp.destination_port)
                    print('here')
                    stream_index = p.tcp.stream_index
                # if p.tcp.stream_index == stream_index:
                #     if p.tcp.actual_data:
                #         f.write(p.tcp.actual_data)
        except Exception:
            print('error')
            traceback.print_exc(file=open('error.log', 'w'))
        print('[---------------------------------------------------------------------------------]')
        tail = list(packet[1])
        tail[4] = str2hex(tail[4])
        print (str2hex(header))
        print(tail)
        break
