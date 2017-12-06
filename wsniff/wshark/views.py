# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse
import subprocess
import os
import signal
from django.shortcuts import render
from .models import PacketM, EtherM, ArpM
from .proto import hexstr2bytes, str2hex, get_interfaces


# Create your views here.

class Http(object):
    postfix_dict = {b'html': b'html', b'jpeg': b'jpg', b'gif': b'gif', b'png': b'png', b'x-javascript': b'js', b'javascript': b'js', b'css': b'css', b'nono': b'nono'}

    def __init__(self, request_header=None, reponse_header=None, response_data=None):
        self.request_header = None
        self.response_header = None
        self.response_data = None
        self.req_dict = {}
        self.res_dict = {}

    def parse(self):
        self.req_list = self.request_header.split(b'\r\n')
        self.req = self.req_list[0]
        for item in self.req_list[1:]:
            if b':' in item:
                key_value = item.split(b':')
                self.req_dict[key_value[0]] = b':'.join(key_value[1:]).strip()
        self.res_list = self.response_header.split(b'\r\n')
        self.res = self.res_list[0]
        for item in self.res_list[1:]:
            if b':' in item:
                key_value = item.split(b':')
                self.res_dict[key_value[0]] = b':'.join(key_value[1:]).strip()
        try:
            self.content_type = self.res_dict[b'Content-Type'].split(b';')[0].split(b'/')[1]
        except:
            self.content_type = b'nono'

    def download_file(self):
        print('content-type', self.content_type)
        if self.content_type in Http.postfix_dict:
            filename = (self.req+b'.'+Http.postfix_dict[self.content_type]).replace(b'/', b'').replace(b' ', b'_')
            filename = b'tmp/'+filename
            print(filename)
            with open(filename, 'wb') as f:
                f.write(self.response_data)
        else:
            filename = (self.req + b'.' + self.content_type).replace(b'/', b'').replace(b' ', b'_')
            filename = b'tmp/' + filename
            with open(filename, 'wb') as f2:
                f2.write(self.response_data)


class Ftp(object):
    def __init__(self):
        self.passive_port = None
        self.file_stream_index = None

    def get_passiveport(self):
        pass
    def download_file(self):
        pass


class HttpFile(object):
    def __init__(self, stream_index):
        self.tcpstream = TcpStream(stream_index)


    def get_request_file(self):
        pass

    def get_content_type(self):
        pass

    def get_file_list(self):
        pass

    def get_http(self):
        return httplist(self.tcpstream.packets_data)


def httplist(packets, httpl=[]):
    print("len", len(packets))
    if len(packets) < 1:
        print('return', httpl)
        return httpl
    else:
        http = Http()
        http.request_header = hexstr2bytes(packets[0].tcpm.actual_data)
        print('requset_header', packets[0].id)
        http.response_header = hexstr2bytes(packets[1].tcpm.actual_data).split(b'\r\n\r\n')[0]
        http.response_data = hexstr2bytes(packets[1].tcpm.actual_data).split(b'\r\n\r\n')[1]
        j = 2
        for packet in packets[2:]:
            if packet.proto != 'http':
                http.response_data += hexstr2bytes(packet.tcpm.actual_data)
            else:
                break
            j = j + 1
        httpl.append(http)
        print("httpl ", httpl)
        httplist(packets[j:], httpl)




class TcpStream(object):
    def __init__(self, stream_index):
        self.proto = None
        self.packets = PacketM.objects.filter(tcpm__stream_index=stream_index)
        self.packets_data = PacketM.objects.filter(tcpm__stream_index=stream_index, tcpm__segment_data_length__gt=0).all()  #tcpm.segment_data_length >0
        # self.handshake1_packet = PacketM.objects.get(tcpm__stream_index=stream_index, tcpm__syn=1, tcpm__ack=0)
        # self.handshake2_packet = PacketM.objects.get(tcpm__stream_index=stream_index, tcpm__syn=1, tcpm__ack=1)
        # self.init_seqX = None
        # self.init_seqY = None
        # if self.handshake1_packet and self.handshake2_packet:
        #     self.init_seqX = self.handshake1_packet.tcpm.sequence_number
        #     self.init_seqY = self.handshake2_packet.tcpm.sequence_number
        # self.delete_dup()
        self.get_order()
        self.delete_dup()
        self.get_proto()

    def get_order(self):
        # ordered_packet = []
        # next_seq = self.init_seqX+1
        # next_ack = self.init_seqY+1
        # for i in range(self.packets_data.count()):
        #     the_packet = self.packets_data.filter(tcpm__sequence_number=next_seq, tcpm__acknowledgement_number=next_ack)
        #     ordered_packet.append(the_packet)
        #     next_seq = the_packet.tcpm.acknowledgement_number
        #     next_ack = the_packet.tcpm.sequence_number + the_packet.tcpm.segment_data_length
        self.packets_data = sorted(self.packets_data, key=lambda t: t.tcpm.order_number())

    # def delete_dup(self):
    #     checksums = []
    #     packets_no_dup = []
    #     for packet in self.packets_data:
    #         if packet.tcpm.checksum not in checksums:
    #             checksums.append(packet.tcpm.checksum)
    #             packets_no_dup.append(packet)
    #     self.packets_data = packets_no_dup  #may have bug

    def delete_dup(self):
        checksums = []
        packets_no_dup = []
        for packet in self.packets_data:
            if (packet.tcpm.sequence_number+packet.tcpm.acknowledgement_number) not in checksums:
                checksums.append(packet.tcpm.sequence_number+packet.tcpm.acknowledgement_number)
                packets_no_dup.append(packet)
        self.packets_data = packets_no_dup  #may have bug

    def get_proto(self):
        if self.packets_data[0].tcpm.source_port == 80 or self.packets_data[0].tcpm.destination_port == 80:
            self.proto = 'http'
        elif self.packets_data[0].tcpm.source_port == 21 or self.packets_data[0].tcpm.destination_port == 21:
            self.proto = 'ftp'




    def check_dup(self):
        pass


def index(request):

    if 'start' in request.GET:
        start = request.GET['start']
        if start == 'on':
            interface = request.GET['interface']
            print(interface)
            if 'start' not in request.session:
                print(os.path.dirname(__file__))
                proc = subprocess.Popen(['python3', os.path.dirname(__file__)+'/wsniffer.py', interface])
                request.session['pid'] = proc.pid
                request.session['start'] = 'on'
        if start == 'off':
            del request.session['start']
            pid = int(request.session['pid'])
            print(pid)
            # os.kill(pid, signal.SIGKILL)
            os.kill(pid, signal.SIGALRM)
        if start == 'clear':
            del request.session['start']

    if 'filter' in request.GET:
        print('filter')
        source_port = ''
        source_ip = ''
        destination_port = ''
        destination_ip = ''
        proto = request.GET['proto']
        if ':' in request.GET['source']:
            source_ip = request.GET['source'].split(':')[0]
            source_port = request.GET['source'].split(':')[1]
        if ':' in request.GET['destination']:
            destination_ip = request.GET['destination'].split(':')[0]
            destination_port = request.GET['destination'].split(':')[1]
        packets = PacketM.objects.all()
        if source_ip != '':
            packets = packets.filter(ipm__source=source_ip)
        if source_port != '':
            source_port = int(source_port)
            packets = packets.filter(tcpm__source_port=source_port)
        if destination_ip != '':
            packets = packets.filter(ipm__destination=destination_ip)
        if destination_port != '':
            packets = packets.filter(tcpm__destination_port=destination_port)
        if proto != '':
            packets = packets.filter(proto=proto)
        context = {'packets': packets}
    elif 'keyword' in request.GET:
        print(type(request.GET['keyword']))
        print(request.GET['keyword'])
        keyword = str2hex(request.GET['keyword'])
        key_packets = PacketM.objects.filter(tcpm__actual_data__contains=keyword)
        actual_datas = []

        for packet in key_packets:
            actual_datas.append(((hexstr2bytes(packet.tcpm.actual_data),), packet))
        context = {'key_packets': key_packets, 'actual_datas': actual_datas}
    else:
        packets = PacketM.objects.all().order_by('-id')

        if 'delete' in request.GET:
            packets.delete()
        # return HttpResponse("Hello, world. you're at the wsahrk index.")
        context = {'packets': packets[:100]}
    interfaces = get_interfaces()
    context['interfaces'] = interfaces
    return render(
        request,
        'wshark/index.html',
        context
        )


def packet_detail(request, id):
    packet = PacketM.objects.get(pk=id)
    actual_data = 'nodata'
    context = {'packet': packet}
    if hasattr(packet, 'tcpm'):
        if packet.tcpm.actual_data:
            actual_data = (hexstr2bytes(packet.tcpm.actual_data),)
        context = {'packet': packet, 'actual_data': actual_data}

    return render(request, 'wshark/packet.html', context=context)

def stream(request, stream_index):
    # packets = PacketM.objects.filter(tcpm__stream_index=stream_index).order_by('id')
    thestream = TcpStream(stream_index=stream_index)
    print('haha', thestream)
    actual_datas = []
    ftp_data_stream_index = None

    for packet in thestream.packets_data:
        print(packet.id)
        if packet.tcpm.segment_data_length > 0:
            print(packet.tcpm.actual_data)
            actual_datas.append((hexstr2bytes(packet.tcpm.actual_data),))
    print(thestream.proto)
    if thestream.proto == 'http':
        httpl = []
        httplist(thestream.packets_data, httpl)
        print(httpl)
        for http in httpl:
            # print(http.request_header)
            # print(http.response_header)
            http.parse()
            # print(http.req)
            # print(http.res)
            # print(http.req_dict)
            # print(http.res_dict)
            # print(http.content_type)
            http.download_file()
            # print(http.req_list)
            # print(http.res_list)
            # print(http.response_data)
    elif thestream.proto == 'ftp':
        thepacket = thestream.packets.filter(tcpm__actual_data__contains = str2hex('227 Entering Passive Mode'))[0]
        p1 = hexstr2bytes(thepacket.tcpm.actual_data).split(b',')[4]
        p2 = hexstr2bytes(thepacket.tcpm.actual_data).split(b',')[5].split(b')')[0]
        pasprot = int(p1)*256+int(p2)
        print(pasprot)
        ftpdatapacket = PacketM.objects.filter(tcpm__source_port=pasprot)[0]
        print(ftpdatapacket.tcpm.stream_index)
        ftp_data_stream_index = ftpdatapacket.tcpm.stream_index
    datas = b''
    if 'import' in request.GET:
        for data in actual_datas:
            datas += data[0]
        response = HttpResponse(datas, content_type='application//html')
        return response

    context = {'actual_datas': actual_datas, 'stream_index': ftp_data_stream_index}
    return render(request, 'wshark/stream.html', context=context)