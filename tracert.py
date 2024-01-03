import socket
import struct
import time

HOST = "127.0.0.1"
SEND_PORT = 33434
RECV_PORT = 50021
TIMEOUT = 2  # 2 seconds

class ReturnArgs:
    def __init__(self):
        self.ok = False
        self.done = False
        self.addr = ""
        self.ip = ""
        self.elapsed = 0.0

def main():
    host = "8.8.8.8"
    try:
        addresses = socket.gethostbyname_ex(host)[2]
        address = addresses[0]
        print(f"Host = {host}")
        print(f"addr = {address}")
        print(f"traceroute {host} {address} 30")

        traceroute(address, 30)
    except Exception as e:
        exit_with_error(e)

def traceroute(address, max_ttl):
    done = False
    for ttl in range(1, max_ttl + 1):
        info = f"{ttl} "
        for _ in range(3):
            rr = trace_one(address, ttl)
            if rr.done:
                done = True
            if rr.ok:
                info += f"{rr.addr} ({rr.ip}) {rr.elapsed:.2f}ms"
            else:
                info += "*"
            if _ != 2:
                info += "  "
        print(info)
        if done:
            break

def trace_one(address, ttl):
    send = None
    receive = None
    #udp = socket.getprotobyname('udp')
    try:
        receive = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        receive.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)

        send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #receive.bind((HOST, RECV_PORT))
        receive.settimeout(TIMEOUT)
        send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        rr = ReturnArgs()
        start_time = time.time()
        send_udp(send, address, ttl)
        try:
            data, ret_ip = receive.recvfrom(1024)
        except socket.timeout:
            return rr

        rr.elapsed = (time.time() - start_time) * 1000
        icmp_values = parse_icmp(data)

        if icmp_values[0] == 3 and icmp_values[1] == 3:
            rr.done = True
        elif icmp_values[0] != 11:
            return rr

        rr.ok = True
        #rr.ip = receive.getpeername()[0]
        rr.ip = ret_ip[0]
        #rr.addr = get_host_name(rr.ip)
        rr.addr = ret_ip[0]

        return rr
    except Exception as e:
        exit_with_error(e)
    finally:
        if send:
            send.close()
        if receive:
            receive.close()

def parse_icmp(data):
    icmp_values = [data[20], data[21]]
    return icmp_values


def send_udp(sock, address, ttl):
    source_address = socket.gethostbyname(socket.gethostname())
    data = "Hello, UDP!".encode()
    udp_packet = make_udp(source_address, RECV_PORT, address, SEND_PORT, data)
    sock.sendto(udp_packet, (address, SEND_PORT))

def get_host_name(ip):
    try:
        host_name, _, _ = socket.gethostbyaddr(ip)
        return host_name
    except socket.herror:
        return ip

def exit_with_error(error):
    print(f"Error: {error}")
    exit(1)

def make_udp(source_address, source_port, destination_address, destination_port, data):
    # UDP header consists of 8 bytes
    udp_header = struct.pack("!HHHH", source_port, destination_port, 8 + len(data), 0)

    # Concatenate the UDP header and data
    udp_packet = udp_header + data

    return udp_packet


if __name__ == "__main__":
    main()
