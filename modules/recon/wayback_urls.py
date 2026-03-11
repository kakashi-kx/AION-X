import requests
import time

def get_wayback_urls(domain):
    api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit=50"

    for attempt in range(3):  # retry 3 times
        try:
            response = requests.get(api, timeout=8)

            if response.status_code == 200:
                data = response.json()

                urls = []
                for entry in data[1:]:
                    urls.append(entry[0])

                return {
                    "domain": domain,
                    "total_urls": len(urls),
                    "urls": urls
                }

        except requests.exceptions.Timeout:
            time.sleep(2)

    return {
        "error": "Wayback request timed out after multiple attempts"
    }
