# full_scan.py
import asyncio
from modules.analysis.attack_surface import build_attack_surface
from modules.recon.recon_engine import run_full_recon

async def main():
    # ----------------------------
    # Step 1: Input target domain
    # ----------------------------
    domain = input("Enter the domain to scan: ").strip()

    print(f"\n[+] Running full scan on {domain} ... this may take a few seconds (async vuln scans).")

    # ----------------------------
    # Step 2: Run full recon + vuln scan
    # ----------------------------
    result = await run_full_recon(domain)

    # ----------------------------
    # Step 3: Display summary
    # ----------------------------
    print("\n===== Scan Summary =====")
    subdomains = result['subdomains'].get('subdomains', [])
    live_hosts = result['live_hosts'].get('live_hosts', [])
    print(f"Subdomains found: {len(subdomains)}")
    print(f"Live hosts: {len(live_hosts)}")
    print(f"Directories found: {len(result['directories'])}")
    print(f"JS Endpoints: {len(result['js_endpoints'])}")
    print(f"Parameters discovered: {len(result['parameters'])}")
    print(f"Technology stack: {result['technology']}\n")

    # ----------------------------
    # Step 4: Show vulnerabilities
    # ----------------------------
    vulns = result['vulnerabilities']
    print("===== Vulnerabilities =====")
    for vtype, vlist in vulns.items():
        print(f"{vtype.upper()}: {len(vlist)} issue(s)")
        for v in vlist:
            line = v.get("url") or v.get("endpoint") or v.get("file") or "N/A"
            score = v.get("score", "N/A")
            print(f" - {line} (score: {score})")
    print("\n[+] Full scan completed!")

# ----------------------------
# Run the async main loop
# ----------------------------
if __name__ == "__main__":
    asyncio.run(main())
