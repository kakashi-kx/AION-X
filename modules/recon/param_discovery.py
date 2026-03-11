import re

def find_parameters(urls):

    params = set()

    for url in urls:
        matches = re.findall(r"[?&]([^=]+)=", url)

        for p in matches:
            params.add(p)

    return {
        "total_parameters": len(params),
        "parameters": list(params)
    }
