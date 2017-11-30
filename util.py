import time
import subprocess,re

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


def get_ipv4(strbyte):
    ipv4 = str2byte(strbyte)
    ipv4 = '.'.join([str(int(i,16)) for i in ipv4])
    return ipv4

def get_ipv6(strbyte):
    ipv6 = ':'.join([strbyte[i:i+4] for i in range(0,len(strbyte),4)])
    return ipv6
def get_timestamp(strbyte):
    '''
    2017-11-28 10:00:00
    '''
    strtime = ''
    for i in range(len(strbyte)//2-1,-1,-1):
        strtime += strbyte[2*i:2*i+2]
    st = time.localtime(int(strtime,16))
    return time.strftime('%Y-%m-%d %H:%M:%S',st)

