import requests

def find_subdomains(domain):
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            data = response.json()

            for entry in data:
                name = entry["name_value"]
                for sub in name.split("\n"):
                    if domain in sub:
                        subdomains.add(sub.strip())

    except Exception as e:
        return {"error": str(e)}

    return {
        "domain": domain,
        "subdomains": list(subdomains),
        "total_found": len(subdomains)
    }
