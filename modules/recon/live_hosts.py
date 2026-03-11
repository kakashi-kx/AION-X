import requests

def check_live_hosts(subdomains):

    live_hosts = []

    for sub in subdomains:

        for protocol in ["http://", "https://"]:
            url = protocol + sub

            try:
                r = requests.get(url, timeout=3)

                if r.status_code < 500:
                    live_hosts.append(url)
                    break

            except:
                pass

    return {
        "live_hosts": live_hosts,
        "total_live": len(live_hosts)
    }
