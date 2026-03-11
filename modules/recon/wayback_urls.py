import requests

def get_wayback_urls(domain):
    try:
        api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=20"

        r = requests.get(api, timeout=5)

        if r.status_code != 200:
            return {"message": "Wayback API not responding right now"}

        data = r.json()
        urls = [entry[0] for entry in data[1:]]

        return {
            "domain": domain,
            "total_urls": len(urls),
            "urls": urls
        }

    except Exception:
        return {
            "message": "Wayback service slow or unreachable",
            "suggestion": "try again later"
        }
