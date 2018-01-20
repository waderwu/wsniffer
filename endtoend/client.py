import socket


def clinet(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0',55555))
    s.connect((host, port))
    s.sendall(b'Hello, world')
    s.shutdown(socket.SHUT_WR) #告诉对方自己已经发完了即对方的s.recv()为空
    while True:
        data = s.recv(1024)
        print('Received', repr(data))
        if not data:break
    s.close()
def server(host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host,port))
        s.listen(1)
        conn,addr = s.accept()
        with conn:
            print('Connect by', addr)
            while True:
                conn.sendall(b'wader')
                data = conn.recv(1024)
                print(repr(data))
                if not data:break
                conn.sendall(data)
        return addr
if __name__ == '__main__':
    # shost = '115.159.147.123'    # The remote host
    shost = '10.162.119.76'
    sport = 50007              # The same port as used by the server
    clinet(shost,sport)
    server('',55555)
