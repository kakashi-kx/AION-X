import re

patterns = [
r"/user/\d+",
r"/account/\d+",
r"id=\d+"
]

def detect_idor(endpoints):

    results = []

    for url in endpoints:
        for p in patterns:

            if re.search(p,url):
                results.append({
                    "type":"Possible IDOR",
                    "endpoint":url
                })

    return results
