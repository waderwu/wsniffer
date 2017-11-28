import socket
import traceback
from django.db import transaction
from proto import Packet, str2hex
import os, sys, django

path = os.path.dirname(__file__)
sys.path.append(path+'/../')
# sys.path.append("/home/waderwu/code/py/wsniffer/wsniff")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wsniff.settings")
django.setup()
from wshark.models import PacketM, ArpM, EtherM, TcpM, IpM

sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))


def sniff(ifrace='wlp5s0'):
    sniffer.bind((ifrace, 0))
    i = 1
    while True:
        packet = sniffer.recvfrom(65565)
        header = packet[0]
        try:
            with transaction.atomic():
                p = Packet(str2hex(header))
                if p.proto:
                    pa = PacketM(id=i, proto=p.proto)
                    pa.save()
                    eth = EtherM(packet=pa, d_mac=p.ether.d_mac, s_mac=p.ether.s_mac, type=p.ether.type, next_proto=p.ether.next_proto)
                    eth.save()
                    if pa.proto == 'arp':
                        arp = ArpM(packet=pa, hardware_size=p.arp.hardware_size, hardware_type=p.arp.hardware_type, protocol_size=p.arp.protocol_size, protocol_type=p.arp.protocol_type, opcode=p.arp.opcode, sender_mac_address=p.arp.sender_mac_address, sender_ip_address=p.arp.sender_ip_address, target_ip_address=p.arp.target_ip_address, target_mac_address=p.arp.target_mac_address)
                        arp.save()
                    if pa.proto == 'tcp' or pa.proto =='http' or pa.proto == 'TSL':
                        ip = IpM(packet=pa, version=p.ip.version, header_length=p.ip.header_length, dsf=p.ip.dsf, total_length=p.ip.total_length, indentification=p.ip.indentification, flags=p.ip.flags, fragment_offset=p.ip.fragment_offset, time_to_live=p.ip.time_to_live, next_proto=p.ip.next_proto, checksum=p.ip.checksum, source=p.ip.source, destination=p.ip.destination)
                        ip.save()
                        tcp = TcpM(packet=pa, source_port=p.tcp.source_port, destination_port=p.tcp.destination_port, sequence_number=p.tcp.sequence_number, acknowledgement_number=p.tcp.acknowledgement_number, header_length=p.tcp.header_length, syn=p.tcp.syn, ack=p.tcp.ack, push=p.tcp.push, fin=p.tcp.fin, window_size_value=p.tcp.window_size_value, checksum=p.tcp.checksum, urgent_pointer=p.tcp.urgent_pointer, options=p.tcp.options, segment_data_length=p.tcp.segment_data_length, actual_data=p.tcp.actual_data, next_proto=p.tcp.next_proto, stream_index=p.tcp.stream_index,)
                        tcp.save()
        except Exception:
            print('error')
            traceback.print_exc(file=open('error.log', 'w'))
        i = i + 1
if __name__ == '__main__':
    packets = PacketM.objects.all().delete()
    sniff()