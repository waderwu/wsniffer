def str2hex(packet):
    '''
    b'aa' => '6161'
    'aa'  => '6161'
    '''
    if (isinstance(packet,str)):
        return "".join("{:02x}".format(ord(c)) for c in packet)
    if (isinstance(packet,bytes)):
        return packet.hex()


def str2byte(string):
    '''
    '6161' => ['61','61']
    '''

    return [string[i:i+2] for i in range(0,len(string),2)]


def byte2bin(hexstr):
    '''
    03 => '00000011'
    '''
    length = len(hexstr)*4
    formats = '{:0%db}'%length

    return formats.format(int(hexstr,16))


def hexstr2unicode(hexstr):
    '''
    '61' -> b'a'->'a'
    '''
    hexlist = str2byte(hexstr)
    hexlist = [int(i,16) for i in hexlist]
    byte = bytes(hexlist)

    return byte.decode()


def hexstr2bytes(hexstr):
    '''
        '61' -> b'a'
        '''
    hexlist = str2byte(hexstr)
    hexlist = [int(i, 16) for i in hexlist]
    byte = bytes(hexlist)

    return byte


def get_mac(strbyte):
    return ":".join(str2byte(strbyte))


def get_ip(strbyte):
    ip = str2byte(strbyte)
    ip = '.'.join([str(int(i,16)) for i in ip])
    return ip


def get_timestamp(strbyte):
    '''
    '''
    return 'will be done'


class Ether(object):
    next_proto_map = {'0806': 'arp', '0800': 'ipv4', '86dd': 'ipv6'}
    header_length = 14  # bytes

    def __init__(self, header):
        self.d_mac = get_mac(header[:12])
        self.s_mac = get_mac(header[12:24])
        self.type = header[24:28]
        self.next_proto = Ether.next_proto_map[self.type]

    def summary(self):
        print("d_mac : %s" % self.d_mac)
        print("s_mac : %s" % self.s_mac)
        print("next proto : %s" % self.next_proto)


class Arp(object):
    header_length = 28*2

    def __init__(self, header):
        self.hardware_type = header[:4]
        self.protocol_type = header[4:8]
        self.hardware_size = header[8:10]
        self.protocol_size = header[10:12]
        self.opcode = header[12:16]
        self.sender_mac_address = get_mac(header[16:28])
        self.sender_ip_address = get_ip(header[28:36])
        self.target_mac_address = get_mac(header[36:48])
        self.target_ip_address = get_ip(header[48:56])

    def summary(self):
        print('----ARP---')
        print('opcode %s ' % self.opcode)
        print('sender_ip_address %s ' % self.sender_ip_address)
        print('sender_mac_address %s ' % self.sender_mac_address)
        print('target_ip_address %s ' % self.target_ip_address)
        print('target_mac_address %s ' % self.target_mac_address)


class Ip(object):
    # header_length = 20*2
    next_proto_map = {'06': 'tcp', '11': 'udp', '01': 'icmp'}

    def __init__(self, header):
        self.version = header[0]
        self.header_length = int(header[1], 16)*4  # bytes
        self.dsf = header[2:4]
        self.total_length = int(header[4:8], 16)  # bytes
        self.indentification = header[8:12]
        self.flags = byte2bin(header[12:14])[:3]
        self.fragment_offset = byte2bin(header[12:16])[3:]
        self.time_to_live = header[16:18]  # ttl
        self.next_proto = Ip.next_proto_map[header[18:20]]
        self.checksum = header[20:24]
        self.source = get_ip(header[24:32])
        self.destination = get_ip(header[32:40])

    def summary(self):
        print('----IP----')
        print('version %s ' % self.version)
        print('header_length %d ' % self.header_length)
        print('total_length %d ' % self.total_length)
        print('next_proto %s ' % self.next_proto)
        print('source %s ' % self.source)
        print('destination %s ' % self.destination)


class Icmp(object):
    header_length = 16*2

    def __init__(self,data):
        self.type_ = data[:2]
        self.code = data[2:4]
        self.checksum = data[4:8]
        self.identifier_be = data[8:12]
        self.identifier_le = self.identifier_be[2:4]+self.identifier_be[:2]
        self.sequence_number_be = data[12:16]
        self.sequence_number_le = self.sequence_number_be[2:4]+self.sequence_number_be[:2]
        self.timestamp_from_icmp_data = get_timestamp(data[16:32])
        self.data_length = len(data[32:])//2
        self.data = data[32:]

    def summary(self):
        print('----ICMP----')
        print(self.data)


class Tcp(object):
    def __init__(self, data, tcp_total_length):
        '''
        data be the part of tcp
        tcp_total_length = ip.total_length - ip_header_length
        '''
        self.source_port = int(data[:4], 16)
        self.destination_port = int(data[4:8], 16)
        self.sequence_number = int(data[8:16], 16)
        self.acknowledgement_number = int(data[16:24], 16)
        self.header_length = int(data[24], 16)*4  # bytes
        self.flags = byte2bin(data[25:28])[3:]
        self.syn = self.flags[7]
        self.ack = self.flags[4]
        self.push = self.flags[5]
        self.fin = self.flags[8]
        self.window_size_value = int(data[28:32], 16)
        self.checksum = data[32:36]
        self.urgent_pointer = data[36:40]
        self.options = data[40:self.header_length*2]
        self.segment_data_length = tcp_total_length - self.header_length
        self.actual_data = None
        self.next_proto = None
        self.stream_index = self.get_stream()
        self.get_proto(data)

    def get_stream(self):
        return self.source_port + self.destination_port

    def get_data(self, data):
        if self.segment_data_length > 0:
            self.actual_data = data[self.header_length*2:]
            return self.actual_data
        return 'no data'

    def get_proto(self, data):
        if self.segment_data_length > 0:
            if self.source_port == 80 or self.destination_port == 80:
                self.get_data(data)
                if str2hex('HTTP/') in self.actual_data:
                    self.next_proto = 'http'
            elif self.source_port == 443 or self.destination_port == 443:
                self.next_proto = 'TSL'

    def summary(self):
        print('----TCP----')
        print('source_port : %d' % self.source_port)
        print('destination_port : %d' % self.destination_port)
        print('sequence_number : %d' % self.sequence_number)
        print('acknowledgement_number : %d' % self.acknowledgement_number)
        print('header_length : %d' % self.header_length)
        print('syn : %s' % self.syn)
        print('ack : %s' % self.ack)
        print('push : %s' % self.push)
        print('fin : %s' % self.fin)
        print('window_size_value : %d' % self.window_size_value)
        print('segment_data_length : %d' % self.segment_data_length)
        if self.actual_data:
            print('---DATA---')
            print(self.actual_data)
        if self.next_proto:
            print('TOP PROTO is : %s' % self.next_proto)


class Dns(object):
    message_type = {'0': 'query', '1': 'response'}
    def __init__(self, header):
        self.transaction_id = header[:4]
        self.questions = int(header[4:8], 16)
        self.flags = byte2bin(header[8:12])
        self.qr = Dns.message_type[self.flags[0]]
        self.answer_rrs = int(header[12:16], 16)
        self.authority_rrs = int(header[16:20], 16)
        self.additional_rrs = int(header[20:24], 16)
        if self.qr == 'query':
            self.query_name = hexstr2bytes(header[24:-8])
            self.query_type = header[-8:-4]
            self.query_class = header[-4:]
        else:
            self.answer_data = header[24:]

    def summary(self):
        print('----DNS----')
        print('query_name : %s' % self.query_name)


class Udp(object):
    def __init__(self, header):
        self.source_port = int(header[:4], 16)
        self.destination_port = int(header[4:8], 16)
        self.length = int(header[8:12], 16)
        self.checksum = header[12:16]

    def stream_index(self):
        pass
    # def get_data(self,header):
    #     if self.length > 8:
    #         if (self.source_port == 53 or self.destination_port ==53):
    #             self.dns = Dns(header[16:])

    def summary(self):
        print('----UDP----')
        print('source_port : %d' % self.source_port)
        print('destination_port : %d' % self.destination_port)
        print('length : %d' % self.length)
        print('checksum : %s' % self.checksum)


class Smtp(object):
    def __init__(self, header):
        pass


class Tsl(object):
    content_type = {'16': 'handshake', '14': 'chang_cipher_spec', '17': 'application_data', '15': 'alert', '18': 'heartbeat'}

    def __init__(self, header):
        self.content_type = Tsl.content_type[header[:2]]
        self.version = header[2:6]
        self.length = int(header[6:10], 16)


class HandShake(object):
    handshake_type = {'00': 'hello_request', '01': 'client_hello', '02': 'server_hello', '0b': 'certificate', '0c': 'server_key_exchange', '0d': 'certificate_requset', '0e': 'server_done', '0f': 'certificate_verify', '10': 'client_key_exchange', '14': 'finished'}

    def __init__(self, header):
        pass


class ChangeCiperSpec(object):

    def __init__(self):
        pass


class Alert(object):

    def __init__(self):
        pass


class ApplicationData(object):

    def __init__(self):
        pass


class Packet(object):
    def __init__(self, raw_packet):
        # self.stream_packet = str2byte(raw_packet)
        # if (isinstance(raw_packet,str)
        self.stream_packet = raw_packet
        header = self.stream_packet[:Ether.header_length*2]
        self.ether = Ether(header)
        self.proto = None
        self.arp = None
        self.ip = None
        self.tcp = None
        self.udp = None
        self.dns = None
        self.icmp = None

        if self.ether.next_proto == 'arp':
            header = self.stream_packet[Ether.header_length*2:]
            self.arp = Arp(header)
            self.proto = 'arp'
        elif self.ether.next_proto == 'ipv4':
            ip_header_length = int(self.stream_packet[Ether.header_length*2+1],16)*4
            header = self.stream_packet[Ether.header_length*2:Ether.header_length*2+ip_header_length*2]
            self.ip = Ip(header)

            if self.ip.next_proto == "tcp":
                tcp_total_length = self.ip.total_length - self.ip.header_length
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:]

                self.tcp = Tcp(header, tcp_total_length)
                if self.tcp.next_proto:
                    self.proto = self.tcp.next_proto
                else:
                    self.proto = 'tcp'

            elif self.ip.next_proto == 'udp':
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:Ether.header_length*2 + ip_header_length*2 + 8*2]
                self.udp = Udp(header)
                self.proto = 'udp'
                if self.udp.source_port == 53 or self.udp.destination_port == 53:
                    self.dns = Dns(self.stream_packet[Ether.header_length*2+ip_header_length*2+8*2:])
                    self.proto = 'dns'
            elif self.ip.next_proto == 'icmp':
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                self.icmp = Icmp(header)
                self.proto = 'icmp'

    def summary(self):
        self.ether.summary()
        if self.ip:
            self.ip.summary()
            if self.tcp:
                self.tcp.summary()
            elif self.icmp:
                self.icmp.summary()
            elif self.udp:
                self.udp.summary()
                if self.dns:
                    self.dns.summary()
            else:
                print("can't judge the proto after ip")
        elif self.arp:
            self.arp.summary()
