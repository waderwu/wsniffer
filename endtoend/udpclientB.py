import socket
import time
import threading

def recv(s,addr):
    while True:
        try:
            data,add = s.recvfrom(1024)
            print ("received:", data, "from", addr)
        except:
            pass

def send(s,addr):
    while True:
        msg = input('p:')
        s.sendto(msg.encode(),addr)


def get_addr(host,port,s):
    address = (host,port)
    data = b'A'
    print('connecting.........')
    while data == b'A':
        s.sendto(b'B',address)
        data,add = s.recvfrom(1024)
        time.sleep(10)
    h,p = data.split(b',')
    addr = (h,int(p))
    print('get addr',addr)
    return addr


def communicate(s,addr):
    tsend = threading.Thread(target=send,args=(s,addr))
    tsend.start()
    trecv = threading.Thread(target=recv,args=(s,addr))
    trecv.start()



if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    host = '127.0.0.1'
    port = 31500
    host = '115.159.147.123'
    addr = get_addr(host,port,s)
    communicate(s,addr)
