# test_vuln.py
from modules.analysis.attack_surface import build_attack_surface
from modules.vuln.vuln_engine import run_vulnerability_scan

# ----------------------------
# Step 1: Dummy Recon Data
# ----------------------------
dummy_recon = {
    "wayback": {"urls": ["https://example.com/?q=test", "https://example.com/search"]},
    "otx_urls": {"urls": ["https://example.com/login", "https://example.com/admin"]},
    "js_endpoints": {"endpoints": ["https://example.com/api/data", "https://example.com/api/user"]},
    "parameters": ["id", "q", "search"]
}

# ----------------------------
# Step 2: Build Attack Surface
# ----------------------------
surface = build_attack_surface(dummy_recon)
print("===== Attack Surface =====")
print(surface)

# ----------------------------
# Step 3: Run Vulnerability Scanners
# ----------------------------
vulns = run_vulnerability_scan(surface)
print("\n===== Vulnerabilities =====")
print(vulns)
