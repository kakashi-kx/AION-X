import requests

payload = "https://evil.com"

redirect_params = [
"redirect",
"url",
"next",
"return",
"dest"
]

def scan_redirect(endpoints):

    results = []

    for url in endpoints:
        for p in redirect_params:

            test_url = f"{url}?{p}={payload}"

            try:
                r = requests.get(test_url, allow_redirects=False)

                if "evil.com" in r.headers.get("Location",""):
                    results.append({
                        "type":"Open Redirect",
                        "url":test_url
                    })

            except:
                pass

    return results
