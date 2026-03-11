import requests

payload = "<script>alert(1)</script>"

def scan_xss(endpoints, params):

    results = []

    for url in endpoints:
        for p in params:

            test_url = f"{url}?{p}={payload}"

            try:
                r = requests.get(test_url, timeout=5)

                if payload in r.text:
                    results.append({
                        "type": "XSS",
                        "url": test_url
                    })

            except:
                pass

    return results
