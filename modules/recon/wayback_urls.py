import requests

def get_wayback_urls(domain):
    urls = set()

    try:
        api = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"

        response = requests.get(api, timeout=30)

        if response.status_code == 200:
            data = response.json()

            for entry in data[1:]:
                urls.add(entry[0])

    except Exception as e:
        return {"error": str(e)}

    return {
        "domain": domain,
        "urls": list(urls),
        "total_urls": len(urls)
    }
