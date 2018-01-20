import socket

def other(addr):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0',9999))
    s.sendto(b'hello, from other', addr)
    s.close()

address = ('0.0.0.0', 31500)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)
Aaddr = b'A'
Baddr = b'B'
while True:
    data, addr = s.recvfrom(2048)
    # other(addr)
    if not data:
        print ("client has exist")
        break
    if data==b'A':
        Aaddr = (addr[0]+',').encode()+str(addr[1]).encode()
        print ("received:", data, "from", addr)
        s.sendto(Baddr,addr)
    elif data==b'B':
        Baddr = (addr[0]+',').encode()+str(addr[1]).encode()
        print ("received:", data, "from", addr)
        s.sendto(Aaddr,addr)
    else:
        s.sendto(data,addr)

s.close()
