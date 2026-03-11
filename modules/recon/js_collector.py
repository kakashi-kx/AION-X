import requests
import re

def collect_js_files(hosts):

    js_files = set()

    for host in hosts:
        try:
            r = requests.get(host, timeout=5)
            matches = re.findall(r'src=["\'](.*?\.js)', r.text)

            for m in matches:
                if m.startswith("http"):
                    js_files.add(m)
                else:
                    js_files.add(host + "/" + m)

        except:
            pass

    return {
        "total_js_files": len(js_files),
        "js_files": list(js_files)
    }
