# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
# class RawPacket(models.Model):
#     raw = models.BinaryField()

class PacketM(models.Model):
    id = models.IntegerField(primary_key=True)
    proto = models.CharField(max_length=50)


class EtherM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )
    d_mac = models.CharField(max_length=50)
    s_mac = models.CharField(max_length=50)
    type = models.CharField(max_length=50)
    next_proto = models.CharField(max_length=50)


class ArpM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )
    hardware_type = models.CharField(max_length=50)
    protocol_type = models.CharField(max_length=50)
    hardware_size = models.CharField(max_length=50)
    protocol_size = models.CharField(max_length=50)
    opcode = models.CharField(max_length=50)
    sender_mac_address = models.CharField(max_length=50)
    sender_ip_address = models.CharField(max_length=50)
    target_mac_address = models.CharField(max_length=50)
    target_ip_address = models.CharField(max_length=50)


class IpM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )
    version = models.CharField(max_length=50)
    header_length = models.CharField(max_length=50)
    dsf = models.CharField(max_length=50)
    total_length = models.CharField(max_length=50)
    indentification = models.CharField(max_length=50)
    flags = models.CharField(max_length=50)
    fragment_offset = models.CharField(max_length=50)
    time_to_live = models.CharField(max_length=50)
    next_proto = models.CharField(max_length=50)
    checksum = models.CharField(max_length=50)
    source = models.CharField(max_length=50)
    destination = models.CharField(max_length=50)



class TcpM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )

    source_port = models.IntegerField()
    destination_port = models.IntegerField()
    sequence_number = models.BigIntegerField()
    acknowledgement_number = models.BigIntegerField()
    header_length = models.IntegerField()
    syn = models.CharField(max_length=50)
    ack = models.CharField(max_length=50)
    push = models.CharField(max_length=50)
    fin = models.CharField(max_length=50)
    window_size_value = models.IntegerField()
    checksum = models.CharField(max_length=50)
    urgent_pointer = models.CharField(max_length=50)
    options = models.TextField()
    segment_data_length = models.IntegerField()
    actual_data = models.TextField(blank=True, null=True, default='')
    next_proto = models.CharField(blank=True, null=True, default='',max_length=50)
    stream_index = models.IntegerField()


class UdpM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )

    # source_port
    # destination_port
    # length
    # checksum



class IcmpM(models.Model):
    packet = models.OneToOneField(
        PacketM,
        on_delete=models.CASCADE,
        primary_key=True
    )

    # type_
    # code
    # checksum
    # identifier_be
    # identifier_le
    # sequence_number_be
    # sequence_number_le
    # timestamp_from_icmp_data
    # data_length
    # data
