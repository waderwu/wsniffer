import socket,sys,traceback
from until import str2hex
from proto import Packet

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sniffer.bind(('wlp5s0', 0))
stream_index = None
f = open('http.txt', 'wb')
while True:
    packet = sniffer.recvfrom(65565)
    header = packet[0]
    # ethernet(str2hex(header))
    try:
        # ethernet(str2hex(header))
        p = Packet(str2hex(header))
        p.summary()
        if p.tcp:
            if not stream_index:
                print(stream_index)
                print(p.tcp.source_port)
                print(p.tcp.destination_port)
                print('here')
                stream_index = p.tcp.stream_index
            if p.tcp.stream_index == stream_index:
                if p.tcp.actual_data:
                    f.write(p.tcp.actual_data)
    except Exception:
        print('error')
        traceback.print_exc(file=open('error.log', 'w'))
    print('[---------------------------------------------------------------------------------]')
    tail = list(packet[1])
    tail[4] = str2hex(tail[4])
    # print (str2hex(header))
    # print(tail)
    # break
