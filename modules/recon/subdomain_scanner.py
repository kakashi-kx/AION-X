import requests

def find_subdomains(domain):

    results = set()

    # Source 1 — crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15)

        for entry in r.json():
            name = entry["name_value"]
            for sub in name.split("\n"):
                if domain in sub:
                    results.add(sub.strip())

    except:
        pass


    # Source 2 — HackerTarget
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=10)

        for line in r.text.splitlines():
            sub = line.split(",")[0]
            results.add(sub)

    except:
        pass


    # Source 3 — ThreatCrowd
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        r = requests.get(url, timeout=10)
        data = r.json()

        for sub in data.get("subdomains", []):
            results.add(sub)

    except:
        pass


    return {
        "total_subdomains": len(results),
        "subdomains": list(results)
    }
