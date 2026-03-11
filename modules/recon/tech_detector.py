import requests

def detect_tech(domain):

    try:
        r = requests.get(f"http://{domain}", timeout=5)

        headers = dict(r.headers)

        return {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "technologies": headers
        }

    except:
        return {"error":"tech detection failed"}
