import socket
import traceback
import netifaces
import threading
from util import str2hex
from proto import Packet

packets = []
numbers = 0
sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

def sniff(ifrace='wlp3s0'):
    global numbers
    sniffer.bind((ifrace, 0))
    while True:
        packet = sniffer.recvfrom(65565)
        header = packet[0]
        try:
            p = Packet(str2hex(header))
            global packets
            packets.append(p)
            # if p.tcp:
            #     if not p.stream_index:
            #         print(p.stream_index)
            #         print(p.tcp.source_port)
            #         print(p.tcp.destination_port)
            #         print('here')
            #         stream_index = p.tcp.stream_index
                # if p.tcp.stream_index == stream_index:
                #     if p.tcp.actual_data:
                #         f.write(p.tcp.actual_data)
        except Exception:
            print('error')
            numbers += 1
            # traceback.print_exc(file=open('error.log', 'w'))

def show_number():
    while True:
        global numbers
        if len(packets) > numbers:
            # for p in packets[numbers:]:
            #     p.summary()
            #     print('--------------------------------------')
            numbers = len(packets)
            print(numbers)
        # print('[---------------------------------------------------------------------------------]')
        # tail = list(packet[1])
        # tail[4] = str2hex(tail[4])
        # print (str2hex(header))
        # print(tail)

t1 = threading.Thread(target=sniff)
t2 = threading.Thread(target=show_number)
t1.start()
t2.start()
t1.join()
t2.join()
# if __name__ == '__main__':
#     interface_list = netifaces.interfaces()
#     for i in interface_list:
#         print(i)
#     print("Please choose the interface you want from the list:")
#     interface = input()
#     sniff(interface)