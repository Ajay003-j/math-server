from threading import Thread
from subprocess import STDOUT,PIPE,Popen
import socket

def start_new_thread(conn,addr):
    t = inputThread(conn,addr)
    t.start()
class OutputThread(Thread):
    def __init__(self,conn,proc):
        Thread.__init__(self)
        self.conn = conn
        self.proc = proc
    def run(self):
        while not self.proc.stdout.closed and not self.conn._closed:
            try:
                self.conn.sendall(self.proc.stdout.readline())
            except:
                pass

class inputThread(Thread):
    def __init__(self, conn,addr):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
    def run(self):
        print(f"{self.addr[0]} is connected with the back port {self.addr[1]}")
        p = Popen(['bc'],stdin=PIPE,stdout=PIPE,stderr=STDOUT)
        out = OutputThread(self.conn,p)
        out.start()
        while not p.stdout.closed or not self.conn._closed:
            try:
                data = self.conn.recv(4096)
                if not data:
                    break
                else:
                    try:
                        data = data.decode()
                        query = data.strip()
                        if query == 'quit' or query == 'exit':
                            p.communicate(query.encode())
                            if p.poll() is not None:
                                break
                        query = query + '\n'
                        p.stdin.write(query.encode())
                        p.stdin.flush()
                    except:
                        pass
            except:
                pass
        self.conn.close()
        
host = ''
port = 5577
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((host,port))
s.listen()
while True:
    conn,addr = s.accept()
    start_new_thread(conn,addr)
s.close()