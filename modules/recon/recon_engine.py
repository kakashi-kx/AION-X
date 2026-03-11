import asyncio
from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls
from modules.recon.otx_urls import get_otx_urls
from backend.scanner import run_scan
from modules.recon.live_hosts import check_live_hosts

async def run_full_recon(domain):

    loop = asyncio.get_event_loop()

    subdomains_task = loop.run_in_executor(None, find_subdomains, domain)
    wayback_task = loop.run_in_executor(None, get_wayback_urls, domain)
    otx_task = loop.run_in_executor(None, get_otx_urls, domain)
    port_task = loop.run_in_executor(None, run_scan, domain)

    subdomains, wayback, otx, ports = await asyncio.gather(
        subdomains_task,
        wayback_task,
        otx_task,
        port_task
    )

    live_hosts = check_live_hosts(subdomains.get("subdomains", []))

    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "wayback": wayback,
        "otx_urls": otx,
        "ports": ports
    }
