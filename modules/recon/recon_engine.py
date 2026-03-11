import asyncio
import aiohttp
import subprocess
from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls
from modules.recon.otx_urls import get_otx_urls
from backend.scanner import run_scan
from modules.recon.live_hosts import check_live_hosts
from modules.recon.param_discovery import find_parameters
from modules.recon.dir_finder import find_directories
from modules.recon.tech_detector import detect_tech
from modules.recon.js_collector import collect_js_files
from modules.recon.js_endpoint_extractor import extract_js_endpoints
from modules.recon.http_mapper import map_http_status
from modules.analysis.attack_surface import build_attack_surface

# ------------------------------
# Async Vulnerability Scanners
# ------------------------------

payload_xss = "<script>alert(1)</script>"
redirect_params = ["redirect","url","next","return","dest"]
sensitive_files = ["robots.txt",".env","config.php","backup.zip"]

async def async_xss_test(session, url, param):
    test_url = f"{url}?{param}={payload_xss}"
    try:
        async with session.get(test_url, timeout=5) as r:
            text = await r.text()
            if payload_xss in text:
                return {"type": "XSS", "url": test_url}
    except:
        return None

async def async_redirect_test(session, url, param):
    payload = "https://evil.com"
    test_url = f"{url}?{param}={payload}"
    try:
        async with session.get(test_url, allow_redirects=False, timeout=5) as r:
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                return {"type": "Open Redirect", "url": test_url}
    except:
        return None

async def async_idor_test(url):
    import re
    patterns = [r"/user/\d+", r"/account/\d+", r"id=\d+"]
    for p in patterns:
        if re.search(p, url):
            return {"type":"IDOR","endpoint":url}
    return None

async def async_sensitive_file_test(session, url):
    results = []
    for f in sensitive_files:
        test_url = f"{url}/{f}"
        try:
            async with session.get(test_url, timeout=3) as r:
                if r.status == 200:
                    results.append({"type":"Sensitive File","url":test_url})
        except:
            continue
    return results

async def run_vulns_async(surface):
    endpoints = surface["endpoints"]
    params = surface["parameters"]
    results = {"xss": [], "open_redirect": [], "idor": [], "sensitive_files": []}

    async with aiohttp.ClientSession() as session:
        tasks = []

        # XSS & Open Redirect
        for url in endpoints:
            for p in params:
                tasks.append(async_xss_test(session, url, p))
                tasks.append(async_redirect_test(session, url, p))
            tasks.append(async_idor_test(url))
            tasks.append(async_sensitive_file_test(session, url))

        completed = await asyncio.gather(*tasks)
        for r in completed:
            if r is None: continue
            # Sensitive file test returns a list
            if isinstance(r, list):
                results["sensitive_files"].extend(r)
            elif r["type"] == "XSS":
                results["xss"].append(r)
            elif r["type"] == "Open Redirect":
                results["open_redirect"].append(r)
            elif r["type"] == "IDOR":
                results["idor"].append(r)

    return results

# ------------------------------
# Nuclei Integration
# ------------------------------

def run_nuclei(targets_file="targets.txt"):
    """
    Run Nuclei scan (requires nuclei installed in system)
    """
    try:
        subprocess.run(["nuclei", "-l", targets_file, "-o", "nuclei_results.txt"])
        return "Nuclei scan completed. Check nuclei_results.txt"
    except Exception as e:
        return f"Nuclei scan failed: {e}"

# ------------------------------
# AI Vulnerability Prioritization
# ------------------------------

def prioritize_vulns(vulns):
    """
    Simple scoring system for vulnerability prioritization
    """
    for vtype, vlist in vulns.items():
        for v in vlist:
            if vtype == "xss": v["score"] = 8
            elif vtype == "idor": v["score"] = 9
            elif vtype == "open_redirect": v["score"] = 6
            elif vtype == "sensitive_files": v["score"] = 7
    return vulns

# ------------------------------
# Full Recon + Vulnerability Scan
# ------------------------------

async def run_full_recon(domain):

    loop = asyncio.get_event_loop()

    # Run core recon asynchronously
    subdomains_task = loop.run_in_executor(None, find_subdomains, domain)
    wayback_task = loop.run_in_executor(None, get_wayback_urls, domain)
    otx_task = loop.run_in_executor(None, get_otx_urls, domain)
    port_task = loop.run_in_executor(None, run_scan, domain)

    subdomains, wayback, otx, ports = await asyncio.gather(
        subdomains_task, wayback_task, otx_task, port_task
    )

    # Live host detection
    live_hosts = check_live_hosts(subdomains.get("subdomains", []))
    hosts = live_hosts.get("live_hosts", [])

    # Directory discovery
    dirs = find_directories(hosts)

    # HTTP status mapping
    http_map = map_http_status(hosts)

    # JavaScript discovery
    js_files = collect_js_files(hosts)

    # JS endpoint extraction
    js_endpoints = extract_js_endpoints(js_files.get("js_files", []))

    # Parameter discovery
    params = find_parameters(otx.get("urls", []))

    # Technology detection
    tech = detect_tech(domain)

    # Build attack surface
    surface = build_attack_surface({
        "wayback": wayback,
        "otx_urls": otx,
        "js_endpoints": js_endpoints,
        "parameters": params
    })

    # Run async vulnerability scan
    vulns = await run_vulns_async(surface)

    # Prioritize vulnerabilities
    vulns = prioritize_vulns(vulns)

    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "http_status": http_map,
        "wayback": wayback,
        "otx_urls": otx,
        "ports": ports,
        "parameters": params,
        "directories": dirs,
        "technology": tech,
        "javascript_files": js_files,
        "js_endpoints": js_endpoints,
        "attack_surface": surface,
        "vulnerabilities": vulns
    }
