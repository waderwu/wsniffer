# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.http import HttpResponse
import subprocess
import os
import signal
from django.shortcuts import render
from .models import PacketM, EtherM, ArpM


# Create your views here.

def index(request):
    # arp1 = PacketM(proto='http')
    # arp1.save()
    if 'start' in request.GET:
        start = request.GET['start']
        if start == 'on':
            print(os.path.dirname(__file__))
            proc = subprocess.Popen(['python3', os.path.dirname(__file__)+'/wsniffer.py'])
            request.session['pid'] = proc.pid
        if start == 'off':
            pid = int(request.session['pid'])
            print(pid)
            os.kill(pid, signal.SIGKILL)

    packets = PacketM.objects.all()

    if 'delete' in request.GET:
        packets.delete()
    # return HttpResponse("Hello, world. you're at the wsahrk index.")
    context = {'packets': packets}
    return render(
        request,
        'wshark/index.html',
        context
        )