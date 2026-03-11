import requests

common_dirs = [
"admin",
"login",
"dashboard",
"api",
"uploads",
"backup",
"config"
]

def find_directories(domain):

    found = []

    for d in common_dirs:

        url = f"http://{domain}/{d}"

        try:
            r = requests.get(url, timeout=3)

            if r.status_code < 404:
                found.append(url)

        except:
            pass

    return {
        "directories_found": found,
        "total": len(found)
    }
