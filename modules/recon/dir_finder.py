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

def find_directories(hosts):

    found = []

    for host in hosts:

        for d in common_dirs:

            url = f"{host}/{d}"

            try:
                r = requests.get(url, timeout=3)

                if r.status_code in [200,301,302,403]:
                    found.append(url)

            except:
                pass

    return {
        "total": len(found),
        "directories_found": found
    }
