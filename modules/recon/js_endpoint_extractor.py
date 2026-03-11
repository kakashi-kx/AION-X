import requests
import re

def extract_js_endpoints(js_files):

    endpoints = set()

    pattern = r'["\'](\/[a-zA-Z0-9_\-\/?=&]+)["\']'

    for js in js_files:
        try:
            r = requests.get(js, timeout=5)

            matches = re.findall(pattern, r.text)

            for m in matches:
                endpoints.add(m)

        except:
            pass

    return {
        "total_endpoints": len(endpoints),
        "endpoints": list(endpoints)
    }
