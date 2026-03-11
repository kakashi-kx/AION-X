from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls
from modules.recon.otx_urls import get_otx_urls
from backend.scanner import run_scan

def run_full_recon(domain):

    results = {}

    # Subdomains
    try:
        results["subdomains"] = find_subdomains(domain)
    except:
        results["subdomains"] = "error"

    # Wayback URLs
    try:
        results["wayback"] = get_wayback_urls(domain)
    except:
        results["wayback"] = "error"

    # OTX URLs
    try:
        results["otx_urls"] = get_otx_urls(domain)
    except:
        results["otx_urls"] = "error"

    # Port scan
    try:
        results["ports"] = run_scan(domain)
    except:
        results["ports"] = "error"

    return results
