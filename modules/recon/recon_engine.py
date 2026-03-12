import asyncio
from typing import Dict, List
from .subdomain_scanner import find_subdomains
from .wayback_urls import get_wayback_urls
from .otx_urls import get_otx_urls
from .live_hosts import check_live_hosts
from .param_discovery import find_parameters
from .dir_finder import find_directories
from .tech_detector import detect_tech
from .http_mapper import map_http_services
from .js_collector import collect_js_files
from .js_endpoint_extractor import extract_endpoints_from_js

async def run_full_recon(target: str) -> Dict:
    """
    Run full reconnaissance on target
    Returns a dictionary with all recon results
    """
    print(f"\n{'='*50}")
    print(f"Starting full reconnaissance for: {target}")
    print(f"{'='*50}\n")
    
    results = {
        "target": target,
        "subdomains": [],
        "urls": {
            "wayback": [],
            "otx": []
        },
        "live_hosts": [],
        "parameters": [],
        "directories": [],
        "technologies": [],
        "http_services": {},
        "js_files": [],
        "js_endpoints": []
    }
    
    # Run recon modules concurrently
    tasks = [
        find_subdomains(target),
        get_wayback_urls(target),
        get_otx_urls(target),
        find_parameters(target),
        find_directories(target),
        detect_tech(target),
        map_http_services(target),
        collect_js_files(target)
    ]
    
    try:
        (results["subdomains"],
         results["urls"]["wayback"],
         results["urls"]["otx"],
         results["parameters"],
         results["directories"],
         results["technologies"],
         results["http_services"],
         results["js_files"]) = await asyncio.gather(*tasks)
        
        # Check live hosts
        all_hosts = [target] + [f"{sub}.{target}" for sub in results["subdomains"]]
        results["live_hosts"] = await check_live_hosts(all_hosts)
        
        # Extract endpoints from JS files
        js_endpoints = []
        for js_file in results["js_files"][:5]:  # Limit to first 5 JS files
            endpoints = await extract_endpoints_from_js(js_file)
            js_endpoints.extend(endpoints)
        results["js_endpoints"] = list(set(js_endpoints))
        
    except Exception as e:
        print(f"[-] Error during reconnaissance: {e}")
    
    # Print summary
    print(f"\n{'='*50}")
    print("Reconnaissance Summary:")
    print(f"Subdomains found: {len(results['subdomains'])}")
    print(f"Wayback URLs: {len(results['urls']['wayback'])}")
    print(f"OTX URLs: {len(results['urls']['otx'])}")
    print(f"Live hosts: {len(results['live_hosts'])}")
    print(f"Parameters found: {len(results['parameters'])}")
    print(f"Directories found: {len(results['directories'])}")
    print(f"Technologies detected: {len(results['technologies'])}")
    print(f"JS files found: {len(results['js_files'])}")
    print(f"JS endpoints found: {len(results['js_endpoints'])}")
    print(f"{'='*50}\n")
    
    return results
