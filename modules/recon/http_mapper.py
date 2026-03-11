import requests

def map_http_status(hosts):

    results = []

    for host in hosts:

        try:
            r = requests.get(host, timeout=5)

            results.append({
                "host": host,
                "status": r.status_code
            })

        except:
            results.append({
                "host": host,
                "status": "unreachable"
            })

    return results
