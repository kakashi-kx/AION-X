import requests

def get_otx_urls(domain):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"

        r = requests.get(url, timeout=10)
        data = r.json()

        urls = []

        if "url_list" in data:
            for entry in data["url_list"]:
                urls.append(entry["url"])

        return {
            "domain": domain,
            "total_urls": len(urls),
            "urls": urls[:50]
        }

    except Exception as e:
        return {"error": str(e)}
