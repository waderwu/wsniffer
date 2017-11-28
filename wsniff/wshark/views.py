# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse
import subprocess
import os
import signal
from django.shortcuts import render
from .models import PacketM, EtherM, ArpM
from .proto import hexstr2bytes, str2hex


# Create your views here.

def index(request):
    # arp1 = PacketM(proto='http')
    # arp1.save()
    if 'start' in request.GET:
        start = request.GET['start']
        if start == 'on':
            if 'start' not in request.session:
                print(os.path.dirname(__file__))
                proc = subprocess.Popen(['python3', os.path.dirname(__file__)+'/wsniffer.py'])
                request.session['pid'] = proc.pid
                request.session['start'] = 'on'
        if start == 'off':
            pid = int(request.session['pid'])
            print(pid)
            os.kill(pid, signal.SIGKILL)
            del request.session['start']
        if start == 'clear':
            del request.session['start']
    if 'keyword' in request.GET:
        print(type(request.GET['keyword']))
        print(request.GET['keyword'])
        keyword = str2hex(request.GET['keyword'])
        key_packets = PacketM.objects.filter(tcpm__actual_data__contains=keyword)
        actual_datas = []

        for packet in key_packets:
            actual_datas.append(((hexstr2bytes(packet.tcpm.actual_data),), packet.tcpm.stream_index))
        context = {'key_packets': key_packets, 'actual_datas': actual_datas}
    else:
        packets = PacketM.objects.all().order_by('-id')

        if 'delete' in request.GET:
            packets.delete()
        # return HttpResponse("Hello, world. you're at the wsahrk index.")
        context = {'packets': packets}
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
    packets = PacketM.objects.filter(tcpm__stream_index=stream_index).order_by('id')
    actual_datas = []

    for packet in packets:
        print(packet.id)
        if packet.tcpm.segment_data_length > 0:
            actual_datas.append((hexstr2bytes(packet.tcpm.actual_data),))

    context = {'actual_datas': actual_datas}
    return render(request, 'wshark/stream.html', context=context)