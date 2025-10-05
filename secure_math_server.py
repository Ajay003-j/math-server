from subprocess import PIPE,Popen,STDOUT
from database import MyDatabase
from threading import Thread
import bcrypt
import socket
import time
import hashlib
import re

host = ''
port = 7788
con = []
cache = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes
login_attempts = {}

class Auth(Thread):
    def __init__(self,conn):
        Thread.__init__(self)
        self.username = None
        self.password = None
        self.conn = conn

    def run(self):
        self.accout_check()

    def accout_check(self):
        try:
            self.conn.sendall(b"Do you have an account yes or no ?: ")
            chooice = self.conn.recv(1024).decode().strip().lower()
            if chooice:
                if chooice == "yes":
                    self.Login()
                elif chooice == "no":
                    self.Sigin()
                else:
                    self.conn.sendall(b"Invalid input please try again ")
                    self.conn.close()
            else:
                self.conn.close()
        except:
            pass

    def Sigin(self):
        try:
            self.conn.sendall(b"Enter your username: ")
            while True:
                self.username = self.conn.recv(1024).decode().strip()
                if self.username:
                    break
                else:
                    self.conn.sendall(b"Please provide username to continue: ")
            self.conn.sendall(b"Enter your password: ")
            while True:
                self.password = self.conn.recv(1024).decode().strip()
                if self.password:
                    break
                else:
                    self.conn.sendall(b"Please provide password to continue: ")
            
            db = MyDatabase.get_conn()
            hashed_pw = bcrypt.hashpw(self.password.encode(), bcrypt.gensalt()).decode()
            cursor = db.cursor()
            try:
                query = "INSERT INTO user (username, password) VALUES (%s, %s)"
                cursor.execute(query, (self.username, hashed_pw))
                db.commit()
                cursor.close()
                db.close()
            except:
                print("somthing went wrong")
            self.conn.sendall(b"Account created successfully.\n")
            
        except Exception as e:
            self.conn.sendall(f"Error: {str(e)}\n".encode())
            self.conn.close()

def Login(self):
    try:
        client_ip = self.conn.getpeername()[0]

        # Lockout check
        if login_attempts.get(client_ip, 0) >= MAX_ATTEMPTS:
            self.conn.sendall(b"Too many attempts. Try again after 5 minutes.\n")
            time.sleep(LOCKOUT_TIME)
            login_attempts[client_ip] = 0

        # Prompt for username
        self.conn.sendall(b"Enter your username: ")
        while True:
            self.username = self.conn.recv(1024).decode().strip()
            if self.username:
                break
            self.conn.sendall(b"Please provide username: ")

        # Retry loop for password
        while True:
            self.conn.sendall(b"Enter your password: ")
            self.password = self.conn.recv(1024).decode().strip()
            if not self.password:
                self.conn.sendall(b"Please provide password: ")
                continue

            # DB check
            try:
                db = MyDatabase.get_conn()
                cursor = db.cursor()
                query = "SELECT password FROM user WHERE username = %s"
                cursor.execute(query, (self.username,))
                result = cursor.fetchone()
                cursor.close()
                db.close()
            except Exception as e:
                self.conn.sendall(f"Database error: {str(e)}\n".encode())
                self.conn.close()
                return

            # Validate credentials
            if result and bcrypt.checkpw(self.password.encode(), result[0].encode()):
                self.conn.sendall(b"Welcome to my Math server\n")
                login_attempts[client_ip] = 0
                break
            else:
                login_attempts[client_ip] = login_attempts.get(client_ip, 0) + 1
                if login_attempts[client_ip] >= MAX_ATTEMPTS:
                    self.conn.sendall(b"Too many attempts. Try again after 5 minutes.\n")
                    time.sleep(LOCKOUT_TIME)
                    login_attempts[client_ip] = 0
                    break
                else:
                    self.conn.sendall(b"Invalid credentials. Try again.\n")

    except Exception as e:
        self.conn.sendall(f"Login error: {str(e)}\n".encode())
        self.conn.close()
        
class outputthread(Thread):
    def __init__(self, p, conn):
        Thread.__init__(self)
        self.p = p
        self.conn = conn
        self.buffer = []

    def run(self):
        try:
            while self.p.poll() is None:
                line = self.p.stdout.readline()
                if line:
                    self.buffer.append(line)
                    self.conn.sendall(line)
        except Exception as e:
            print(f"Output thread error: {e}")

    def get_output(self):
        return (self.buffer)

class inputthread(Thread):
    def __init__(self,conn,addr):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr

    def run(self):
        p = Popen(['bc'],stdout=PIPE,stderr=STDOUT,stdin=PIPE)
        pro = outputthread(p,conn)
        pro.start()
        requests = 0
        while p.poll() is None:
            try:
                inp = self.conn.recv(1024)
                inp = inp.decode().strip()
                  
                if (not inp):
                    p.kill()
                    self.conn.close()
                    con.remove(self.addr[0])
                    break

                elif (inp == "quit" or inp == "exit"):
                    p.kill()
                    self.conn.close()
                    con.remove(self.addr[0])
                    break

                elif inp in cache:
                    try:
                        start_time = time.time()
                        self.conn.sendall(cache[inp])
                        requests += 1
                        p.wait(0.50)
                        last_req_time = time.time()
                        req = Req_rate_limit(start_time,last_req_time)
                        req_time = req.calculate_time()
                    except:
                        pass

                else:
                    output = outputthread(p,self.conn)
                    out = output.get_output()
                    cache[inp] =b''.join(out)

                    if has_large_integer(inp,5):
                        self.conn.sendall(b"Can't process this input\n")
                        continue
                    else:
                        try:
                            start_time = time.time()
                            inp = inp + '\n'
                            p.stdin.write(inp.encode())
                            p.stdin.flush()
                            requests += 1
                            p.wait(1)
                            last_req_time = time.time()
                            req = Req_rate_limit(start_time,last_req_time)
                            req_time = req.calculate_time()

                        except:
                            pass
                    if 'req_time' in locals() and req_time > 60:
                        p.wait(30)
            except Exception as e:
                print(addr[0]+"-"+str(e))
                self.conn.close()
                con.remove(self.addr[0])
            solved = pro.get_output()
            if not solved:
                self.conn.sendall(b"Still working please wait..\n")
                p.wait()
            else:
                continue

class Req_rate_limit():

    def __init__(self,start_time,last_req_time):
        self.start_time = start_time
        self.last_req_time = last_req_time

    def calculate_time(self):
        return self.last_req_time  - self.start_time

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((host,port))
s.listen()

def has_large_integer(expr, max_digits=10):
    # Match either a plain integer, or numbers inside "for var in <int>"
    numbers = re.findall(r"(?:for\s+[a-zA-Z_]\w*\s+in\s+(-?\d+))|(-?\d+)", expr)
    
    # re.findall returns tuples because of groups → flatten them
    flat_numbers = [num for tup in numbers for num in tup if num]

    return any(len(num.lstrip('-')) > max_digits for num in flat_numbers)

while True:
    conn,addr  = s.accept() # accept all incomming connections
    auth = Auth(conn)
    auth.start()
    auth.join()

    if addr[0] in con: # To check the user has already conneted  and make sure the user can create one connection from one ip
        conn.close()
        con.remove(addr[0]) 
        print(f"connection rejected {addr[0]}")
    else:
        con.append(addr[0]) # when the user is connected his ip will be added to the list
    print(f"connected ip {addr[0]} with backport {addr[1]}")
    inp = inputthread(conn,addr)
    inp.start()