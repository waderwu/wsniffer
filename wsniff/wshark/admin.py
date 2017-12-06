# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.contrib import admin
from .models import PacketM, EtherM, ArpM, TcpM, IpM
# Register your models here.


@admin.register(PacketM)
class PacketMAdmin(admin.ModelAdmin):
    list_display = ('id', 'proto', 'timestamp')


@admin.register(EtherM)
class EtherMAdmin(admin.ModelAdmin):
    list_display = ('packet', 'd_mac', 's_mac', 'type', 'next_proto')


@admin.register(ArpM)
class ArpMAdmin(admin.ModelAdmin):
    list_display = ('packet', 'hardware_type', 'protocol_type', 'sender_mac_address', 'sender_ip_address', 'target_ip_address', 'target_mac_address')


@admin.register(TcpM)
class TcpMAdmin(admin.ModelAdmin):
    list_display = ('source_port', 'destination_port', 'syn', 'ack', 'stream_index', 'sequence_number', 'acknowledgement_number', 'checksum', 'segment_data_length')


@admin.register(IpM)
class IpMAdmin(admin.ModelAdmin):
    list_display = ('source', 'destination', 'next_proto', 'total_length')
