import socket

def scan_ports(target, start=1, end=1024):

    open_ports = []

    for port in range(start, end):

        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((target, port))
            open_ports.append(port)
            sock.close()

        except:
            pass

    return open_ports
