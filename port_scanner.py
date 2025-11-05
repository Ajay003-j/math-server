import socket
import sys
import struct

print("\n")
print(r" (                     (                                      ")  
print(r" )\ )              )   )\ )                                    ")
print(r"(()/(      (    ( /(  (()/(         )                  (   (    ")
print(r" /(_)) (   )(   )\())  /(_)) (   ( /(   (      (      ))\  )(   ")
print(r"(_))   )\ (()\ (_))/  (_))   )\  )(_))  )\ )   )\ )  /((_)(()\  ")
print(r"| _ \ ((_) ((_)| |_   / __| ((_)((_)_  _(_/(  _(_/( (_))   ((_) ")
print(r"|  _// _ \| '_||  _|  \__ \/ _| / _` || ' \))| ' \))/ -_) | '_| ")
print(r"|_|  \___/|_|   \__|  |___/\__| \__,_||_||_| |_||_| \___| |_| ")
print("\n\n")
print("Scannig for open ports\n")

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def Ip_Header(src_ip, dest_ip):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 20 + 20
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header_wo_checksum = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr
    )
    ip_sum = checksum(ip_header_wo_checksum)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
        ip_ttl, ip_proto, ip_sum, ip_saddr, ip_daddr
    )
    return ip_header

def TCP_Header(src_ip, dest_ip, src_port, dest_port):
    tcp_seq = 454
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_flags = 2  # SYN
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0

    tcp_header_wo_checksum = struct.pack('!HHLLBBHHH',
        src_port, dest_port, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr
    )

    src_ip_bytes = socket.inet_aton(src_ip)
    dest_ip_bytes = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header_wo_checksum)

    pseudo_header = struct.pack('!4s4sBBH',
        src_ip_bytes, dest_ip_bytes, placeholder, protocol, tcp_length
    )
    tcp_sum = checksum(pseudo_header + tcp_header_wo_checksum)

    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dest_port, tcp_seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, tcp_sum, tcp_urg_ptr
    )
    return tcp_header

def send_rst(src_ip, dest_ip, src_port, dest_port, seq):
    ip_header = Ip_Header(src_ip, dest_ip)

    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_flags = 0x04  # RST
    tcp_window = socket.htons(5840)
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0

    tcp_header_wo_checksum = struct.pack('!HHLLBBHHH',
        src_port, dest_port, seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, 0, tcp_urg_ptr
    )

    pseudo_header = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dest_ip),
        0, socket.IPPROTO_TCP, len(tcp_header_wo_checksum)
    )

    tcp_sum = checksum(pseudo_header + tcp_header_wo_checksum)

    tcp_header = struct.pack('!HHLLBBHHH',
        src_port, dest_port, seq, tcp_ack_seq,
        tcp_offset_res, tcp_flags, tcp_window, tcp_sum, tcp_urg_ptr
    )

    packet = ip_header + tcp_header

# Main
if len(sys.argv) != 3:
    print("\nUsage: python3 scanner.py <-t> <target host>")
    sys.exit(1)

target = sys.argv[2]
dest_ip = socket.gethostbyname(target)
src_ip = "172.24.13.49"
src_port = 12345

s_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
#s_recv.settimeout(2)


for port in range(1,1024):
    ip_header = Ip_Header(src_ip, dest_ip)
    tcp_header = TCP_Header(src_ip, dest_ip, src_port, port)
    packet = ip_header + tcp_header
    s_send.sendto(packet, (dest_ip, 0))

    try:
        data, addr = s_recv.recvfrom(65535)
        ip_header_len = (data[0] & 0x0F) * 4
        tcp_header = data[ip_header_len:ip_header_len+20]
        recv_src_port, recv_dst_port = struct.unpack('!HH', tcp_header[:4])
        flags = tcp_header[13]

        if recv_dst_port == src_port:
            if flags & 0x12 == 0x12:
                recv_seq = struct.unpack('!L', tcp_header[4:8])[0]
                send_rst(src_ip, dest_ip, src_port, port, recv_seq)
                print(f"Port {port} is OPEN")
            elif flags & 0x04:
                print(f"Port {port} is CLOSED")
    except socket.timeout:
        pass 

