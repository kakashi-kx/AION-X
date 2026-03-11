from modules.vuln.xss_scanner import scan_xss
from modules.vuln.open_redirect_scanner import scan_redirect
from modules.vuln.idor_detector import detect_idor

def run_vulnerability_scan(surface):

    endpoints = surface["endpoints"]
    params = surface["parameters"]

    xss = scan_xss(endpoints, params)
    redirect = scan_redirect(endpoints)
    idor = detect_idor(endpoints)

    return {
        "xss": xss,
        "open_redirect": redirect,
        "idor": idor
    }
