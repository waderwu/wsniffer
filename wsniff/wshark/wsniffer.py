import socket
import traceback
from django.db import transaction
from multiprocessing import Process, Queue
from proto import Packet, str2hex
import os, sys, django,signal

path = os.path.dirname(__file__)
sys.path.append(path+'/../')
# sys.path.append("/home/waderwu/code/py/wsniffer/wsniff")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wsniff.settings")
django.setup()
from wshark.models import PacketM, ArpM, EtherM, TcpM, IpM

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)


def save_packet(q):
    import os, sys, django

    path = os.path.dirname(__file__)
    sys.path.append(path + '/../')
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wsniff.settings")
    django.setup()
    i = 1
    while True:
        print(i)
        header = q.get()
        if header =='over':
            break
        p = Packet(str2hex(header))
        with transaction.atomic():
            if p.proto:
                pa = PacketM(id=i, proto=p.proto)
                pa.save()
                eth = EtherM(packet=pa, d_mac=p.ether.d_mac, s_mac=p.ether.s_mac, type=p.ether.type,
                             next_proto=p.ether.next_proto)
                eth.save()
                if pa.proto == 'arp':
                    arp = ArpM(packet=pa, hardware_size=p.arp.hardware_size, hardware_type=p.arp.hardware_type,
                               protocol_size=p.arp.protocol_size, protocol_type=p.arp.protocol_type, opcode=p.arp.opcode,
                               sender_mac_address=p.arp.sender_mac_address, sender_ip_address=p.arp.sender_ip_address,
                               target_ip_address=p.arp.target_ip_address, target_mac_address=p.arp.target_mac_address)
                    arp.save()
                if pa.proto == 'tcp' or pa.proto == 'http' or pa.proto == 'TSL':
                    ip = IpM(packet=pa, version=p.ip.version, header_length=p.ip.header_length, dsf=p.ip.dsf,
                             total_length=p.ip.total_length, indentification=p.ip.indentification, flags=p.ip.flags,
                             fragment_offset=p.ip.fragment_offset, time_to_live=p.ip.time_to_live,
                             next_proto=p.ip.next_proto, checksum=p.ip.checksum, source=p.ip.source,
                             destination=p.ip.destination)
                    ip.save()
                    tcp = TcpM(packet=pa, source_port=p.tcp.source_port, destination_port=p.tcp.destination_port,
                               sequence_number=p.tcp.sequence_number, acknowledgement_number=p.tcp.acknowledgement_number,
                               header_length=p.tcp.header_length, syn=p.tcp.syn, ack=p.tcp.ack, push=p.tcp.push,
                               fin=p.tcp.fin, window_size_value=p.tcp.window_size_value, checksum=p.tcp.checksum,
                               urgent_pointer=p.tcp.urgent_pointer, options=p.tcp.options,
                               segment_data_length=p.tcp.segment_data_length, actual_data=p.tcp.actual_data,
                               next_proto=p.tcp.next_proto, stream_index=p.tcp.stream_index, )
                    tcp.save()
        i = i + 1
    # time.sleep(i % 39)  # j = 100 , 89 基本可以, 39 好像也可以最后尝试19也行
    # with transaction.atomic():
    #     for packet in packets:
    #         p = Packet(str2hex(packet))
    #         if p.proto:
    #             pa = PacketM(id=i, proto=p.proto)
    #             pa.save()
    #             eth = EtherM(packet=pa, d_mac=p.ether.d_mac, s_mac=p.ether.s_mac, type=p.ether.type, next_proto=p.ether.next_proto)
    #             eth.save()
    #             if pa.proto == 'arp':
    #                 arp = ArpM(packet=pa, hardware_size=p.arp.hardware_size, hardware_type=p.arp.hardware_type, protocol_size=p.arp.protocol_size, protocol_type=p.arp.protocol_type, opcode=p.arp.opcode, sender_mac_address=p.arp.sender_mac_address, sender_ip_address=p.arp.sender_ip_address, target_ip_address=p.arp.target_ip_address, target_mac_address=p.arp.target_mac_address)
    #                 arp.save()
    #             if pa.proto == 'tcp' or pa.proto =='http' or pa.proto == 'TSL':
    #                 ip = IpM(packet=pa, version=p.ip.version, header_length=p.ip.header_length, dsf=p.ip.dsf, total_length=p.ip.total_length, indentification=p.ip.indentification, flags=p.ip.flags, fragment_offset=p.ip.fragment_offset, time_to_live=p.ip.time_to_live, next_proto=p.ip.next_proto, checksum=p.ip.checksum, source=p.ip.source, destination=p.ip.destination)
    #                 ip.save()
    #                 tcp = TcpM(packet=pa, source_port=p.tcp.source_port, destination_port=p.tcp.destination_port, sequence_number=p.tcp.sequence_number, acknowledgement_number=p.tcp.acknowledgement_number, header_length=p.tcp.header_length, syn=p.tcp.syn, ack=p.tcp.ack, push=p.tcp.push, fin=p.tcp.fin, window_size_value=p.tcp.window_size_value, checksum=p.tcp.checksum, urgent_pointer=p.tcp.urgent_pointer, options=p.tcp.options, segment_data_length=p.tcp.segment_data_length, actual_data=p.tcp.actual_data, next_proto=p.tcp.next_proto, stream_index=p.tcp.stream_index,)
    #                 tcp.save()


def handler(signum, frame):
    global switch
    switch = 0


def sniff(ifrace='wlp3s0'):
    global switch
    sniffer.bind((ifrace, 0))
    i = 1
    j = 0
    q = Queue()
    proc = Process(target=save_packet, args=(q,))
    proc.start()
    while switch:
        packet = sniffer.recvfrom(65565)
        header = packet[0]
        q.put(header)
        # print(i)
        i = i + 1
        # j = j + 1
    q.put('over')
    print ('the number is ', i)

    # plist = []
    # switch = '1'
    # while switch == '1':
    #     packet = sniffer.recvfrom(65565)
    #     header = packet[0]
    #     # p = Packet(str2hex(header))
    #     # with transaction.atomic():
    #     #     if p.proto:
    #     #         pa = PacketM(id=i, proto=p.proto)
    #     #         pa.save()
    #     #         eth = EtherM(packet=pa, d_mac=p.ether.d_mac, s_mac=p.ether.s_mac, type=p.ether.type,
    #     #                      next_proto=p.ether.next_proto)
    #     #         eth.save()
    #     #         if pa.proto == 'arp':
    #     #             arp = ArpM(packet=pa, hardware_size=p.arp.hardware_size, hardware_type=p.arp.hardware_type,
    #     #                        protocol_size=p.arp.protocol_size, protocol_type=p.arp.protocol_type, opcode=p.arp.opcode,
    #     #                        sender_mac_address=p.arp.sender_mac_address, sender_ip_address=p.arp.sender_ip_address,
    #     #                        target_ip_address=p.arp.target_ip_address, target_mac_address=p.arp.target_mac_address)
    #     #             arp.save()
    #     #         if pa.proto == 'tcp' or pa.proto == 'http' or pa.proto == 'TSL':
    #     #             ip = IpM(packet=pa, version=p.ip.version, header_length=p.ip.header_length, dsf=p.ip.dsf,
    #     #                      total_length=p.ip.total_length, indentification=p.ip.indentification, flags=p.ip.flags,
    #     #                      fragment_offset=p.ip.fragment_offset, time_to_live=p.ip.time_to_live,
    #     #                      next_proto=p.ip.next_proto, checksum=p.ip.checksum, source=p.ip.source,
    #     #                      destination=p.ip.destination)
    #     #             ip.save()
    #     #             tcp = TcpM(packet=pa, source_port=p.tcp.source_port, destination_port=p.tcp.destination_port,
    #     #                        sequence_number=p.tcp.sequence_number, acknowledgement_number=p.tcp.acknowledgement_number,
    #     #                        header_length=p.tcp.header_length, syn=p.tcp.syn, ack=p.tcp.ack, push=p.tcp.push,
    #     #                        fin=p.tcp.fin, window_size_value=p.tcp.window_size_value, checksum=p.tcp.checksum,
    #     #                        urgent_pointer=p.tcp.urgent_pointer, options=p.tcp.options,
    #     #                        segment_data_length=p.tcp.segment_data_length, actual_data=p.tcp.actual_data,
    #     #                        next_proto=p.tcp.next_proto, stream_index=p.tcp.stream_index, )
    #     #             tcp.save()
    #     plist.append(header)
    #     if j > 100:   # 20 对一般访问没有问题, 但是对于优酷这样的就gg了
    #         p = Process(target=save_packet, args=(plist, i,))
    #         p.start()
    #         print(j)
    #         j = 0
    #         plist = []
if __name__ == '__main__':
    signal.signal(signal.SIGALRM, handler)
    packets = PacketM.objects.all().delete()
    # interface_list = netifaces.interfaces()
    # print("Please choose the interface you want from the list:")
    # for i in interface_list:
    #     print(i)
    # interface = input()
    switch = 1
    sniff('wlp5s0')