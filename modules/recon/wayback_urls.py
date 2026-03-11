import requests

def get_wayback_urls(domain):
    try:
        api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=50"

        response = requests.get(api, timeout=10)

        if response.status_code != 200:
            return {"error": "Wayback API error"}

        data = response.json()

        urls = []

        for entry in data[1:]:
            urls.append(entry[0])

        return {
            "domain": domain,
            "total_urls": len(urls),
            "urls": urls
        }

    except Exception as e:
        return {"error": str(e)}
