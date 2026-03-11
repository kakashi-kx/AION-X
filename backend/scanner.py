from modules.network.portscan import scan_ports

def run_scan(target):

    ports = scan_ports(target)

    result = {
        "target": target,
        "open_ports": ports,
        "total_open_ports": len(ports)
    }

    return result
