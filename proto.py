from until import byte2bin,str2hex,str2byte,hexstr2unicode,get_mac,get_ip,get_timestamp

class Ether(object):
    next_proto_map = {'0806':'arp','0800':'ipv4'}
    header_length = 14 #bytes
    def __init__(self,header):
        self.d_mac = get_mac(header[:12])
        self.s_mac = get_mac(header[12:24])
        self.type = header[24:28]
        self.next_proto = Ether.next_proto_map[self.type]

    def summary(self):
        print("d_mac : %s"%self.d_mac)
        print("s_mac : %s"%self.s_mac)
        print("next proto : %s"%self.next_proto)

class Arp(object):
    header_length = 28*2
    def __init__(self,header):
        self.hardware_type = header[:4]
        self.protocol_type = header[4:8]
        self.hardware_size = header[8:10]
        self.protocol.size = header[10:12]
        self.opcode = header[12:16]
        self.sender_mac_address = header[16:28]
        self.sender_ip_address = get_ip(header[28:36])
        self.target_mac_address = get_mac(header[36:48])
        self.target_ip_address = get_ip(header[48:56])
    def summary(self):
        print('----ARP---')
        print('opcode %s '%self.opcode)
        print('sender_ip_address %s '%self.sender_ip_address)
        print('sender_mac_address %s '%self.sender_mac_address)
        print('target_ip_address %s '%self.target_ip_address)
        print('target_mac_address %s '%self.sender_mac_address)

class Ip(object):
    # header_length = 20*2
    next_proto_map = {'06':'tcp','11':'udp','01':'icmp'}
    def __init__(self,header):
        self.version = header[0]
        self.header_length = int(header[1],16)*4 #bytes
        self.dsf = header[2:4]
        self.total_length = int(header[4:8],16) #bytes
        self.indentification = header[8:12]
        self.flags = byte2bin(header[12:14])[:3]
        self.fragment_offset = byte2bin(header[12:16])[3:]
        self.time_to_live = header[16:18] #ttl
        self.next_proto = Ip.next_proto_map[header[18:20]]
        self.checksum = header[20:24]
        self.source = get_ip(header[24:32])
        self.destination = get_ip(header[32:40])

    def summary(self):
        print('----IP----')
        print('version %s '%self.version)
        print('header_length %d '%self.header_length)
        print('total_length %d '%self.total_length)
        print('next_proto %s '%self.next_proto)
        print('source %s '%self.source)
        print('destination %s '%self.destination)


class Icmp(object):
    header_length = 16*2
    def __init__(self,data):
        self.type = data[:2]
        self.code = data[2:4]
        self.checksum = data[4:8]
        self.identifier_be = data[8:12]
        self.identifier_le = self.identifier_be[2:4]+self.identifier_be[:2]
        self.sequence_number_be = data[12:16]
        self.sequence_number_le = self.sequence_number_be[2:4]+self.sequence_number_be[:2]
        self.timestamp_from_icmp_data = get_timestamp(data[16:32])
        self.data_length = len(data[32:])//2
        try:
            self.data = hexstr2unicode(data[32:])
        except:
            self.data = data[32:]
    def summary(self):
        print('----ICMP----')
        print(self.data)

class Tcp(object):
    def __init__(self,data,tcp_total_length):
        '''
            data be the part of tcp
            tcp_total_length = ip.total_length - ip_header_length
        '''
        self.source_port = int(data[:4],16)
        self.destination_port = int(data[4:8],16)
        self.sequence_number = int(data[8:16],16)
        self.acknowledgement_number = int(data[16:24],16)
        self.header_length = int(data[24],16)*4 #bytes
        self.flags = byte2bin(data[25:28])[3:]
        self.syn = self.flags[7]
        self.ack = self.flags[4]
        self.window_size_value = int(data[28:32],16)
        self.checksum = data[32:36]
        self.urgent_pointer = data[36:40]
        self.options = data[40:self.header_length*2]
        self.segment_data_length = tcp_total_length - self.header_length

        self.get_data(data)

    def stream_index(self):
        pass
    def next_proto(self):
        pass
    def get_data(self,data):
        if self.segment_data_length > 0:
            self.actual_data = hexstr2unicode(data[self.header_length*2:])
            return self.actual_data
        return 'nodata'

    def summary(self):
        print('----TCP----')
        print('source_port : %d'%self.source_port)
        print('destination_port : %d'%self.destination_port)
        print('sequence_number : %d'%self.sequence_number)
        print('acknowledgement_number : %d'%self.acknowledgement_number)
        print('header_length : %d'%self.header_length)
        print('syn : %s'%self.syn)
        print('ack : %s'%self.ack)
        print('window_size_value : %d'%self.window_size_value)
        print('segment_data_length : %d'%self.segment_data_length)
        if hasattr(self,'actual_data'):
            print('---DATA---')
            print(self.actual_data)

class Dns(object):
    def __init__(self,header):
        self.transaction_id = header[:4]
        self.questions = int(header[4:8],16)
        self.flags = byte2bin(header[8:12])
        self.answer_rrs = int(header[12:16],16)
        self.authority_rrs = int(header[16:20],16)
        self.additional_rrs = int(header[20:24],16)
        self.query_name = hexstr2unicode(header[24:-8])
        self.query_type = header[-8:-4]
        self.query_class = header[-4:]
    def summary(self):
        print('----DNS----')
        print('query_name : %s'%self.query_name)



class Udp(object):
    def __init__(self,header):
        self.source_port = int(header[:4],16)
        self.destination_port = int(header[4:8],16)
        self.length = int(header[8:12],16)
        self.checksum = header[12:16]
    def stream_index(self):
        pass
    # def get_data(self,header):
    #     if self.length > 8:
    #         if (self.source_port == 53 or self.destination_port ==53):
    #             self.dns = Dns(header[16:])
    def summary(self):
        print('----UDP----')
        print('source_port : %d'%self.source_port)
        print('destination_port : %d'%self.destination_port)
        print('length : %d'%self.length)
        print('checksum : %s'%self.checksum)

class Smtp(object):
    def __init__(self,packet):
        pass

class Packet(object):
    def __init__(self,raw_packet):
        # self.stream_packet = str2byte(raw_packet)
        # if (isinstance(raw_packet,str)
        self.stream_packet = raw_packet
        header = self.stream_packet[:Ether.header_length*2]
        self.ether = Ether(header)

        if (self.ether.next_proto == 'arp'):
            header = self.stream_packet[Ether.header_length*2:]
            self.arp = Arp(header)
        elif(self.ether.next_proto =='ipv4'):
            ip_header_length = int(self.stream_packet[Ether.header_length*2+1],16)*4
            header = self.stream_packet[Ether.header_length*2:Ether.header_length*2+ip_header_length*2]
            self.ip = Ip(header)

            if (self.ip.next_proto =="tcp"):
                tcp_total_length = self.ip.total_length - self.ip.header_length
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:]

                self.tcp = Tcp(header,tcp_total_length)

            elif (self.ip.next_proto =='udp'):
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:Ether.header_length*2+ip_header_length*2+8*2]
                self.udp = Udp(header)
                if (self.udp.source_port == 53 or self.udp.destination_port ==53):
                    self.dns = Dns(self.stream_packet[Ether.header_length*2+ip_header_length*2+8*2:])
            elif (self.ip.next_proto =='icmp'):
                header = self.stream_packet[Ether.header_length*2+ip_header_length*2:]
                self.icmp = Icmp(header)
    def summary(self):
        self.ether.summary()
        if hasattr(self,'ip'):
            self.ip.summary()
            if hasattr(self,'tcp'):
                self.tcp.summary()
            elif hasattr(self,'icmp'):
                self.icmp.summary()
            elif hasattr(self,'udp'):
                self.udp.summary()
                if hasattr(self,'dns'):
                    self.dns.summary()
            else:
                print("can't judge the proto after ip")
