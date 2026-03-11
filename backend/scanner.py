import socket

def run_scan(target):
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]
    open_ports = []

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(1)
            s.connect((target, port))
            open_ports.append(port)
            s.close()
        except:
            pass

    return {
        "target": target,
        "open_ports": open_ports,
        "total_open_ports": len(open_ports)
    }
