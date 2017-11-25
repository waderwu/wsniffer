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
