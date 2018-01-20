import socket
import os


def server(host,port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host,port))
        s.listen(1)

        while True:
            conn,addr = s.accept()
            pid = os.fork()
            if (pid == 0):
                with conn:
                    print('Connect by', addr)
                    while True:
                        conn.sendall(b'wader')
                        data = conn.recv(1024)
                        print(repr(data))
                        if not data:break
                        conn.sendall(data)
                conn.close()
                exit(0)
            conn.close()
if __name__ == '__main__':
    host = ''
    port = 50007
    server(host,port)
