import socket
import select as sel
import sys

soc_list = [sys.stdin]
mess_buff = 4096
def client():
    if len(sys.argv) < 3:
        print(f"Usage:python3 {sys.argv[0]}")
    HOST = sys.argv[1]
    PORT = int(sys.argv[2])
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect((HOST,PORT))
        soc_list.append(s)   
    except:
        print(f"failed connect to {HOST},{PORT}")
        sys.exit(-1)
    print(f"connect to the remote host {HOST}")
    sys.stdout.write("> ")
    sys.stdout.flush()

    while True:
        read_ready,write_ready,error = sel.select(soc_list,[],[],0)
        for sock in read_ready:
            if sock == s:                    
                data = s.recv(mess_buff).decode()
                if not data:
                    print("client is disconnected")                        
                    sys.exit()
                else:
                    sys.stdout.write(data)
                    sys.stdout.write("> ")
                    sys.stdout.flush()
            else:
                msg = sys.stdin.readline()
                s.send(msg.encode())
                sys.stdout.write("> ")
                sys.stdout.flush()
                
if __name__ == "__main__":
    sys.exit(client())