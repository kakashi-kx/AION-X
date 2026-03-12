import aiohttp
import asyncio
from typing import List, Dict, Set
import json

async def fetch_json(session, url):
    """Helper function to fetch JSON asynchronously"""
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                return await response.json()
    except:
        return None

async def fetch_text(session, url):
    """Helper function to fetch text asynchronously"""
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                return await response.text()
    except:
        return None

async def find_subdomains(domain: str) -> List[str]:
    """
    Find subdomains for a given domain using multiple sources
    Returns a list of subdomains (not a dictionary)
    """
    print(f"[*] Searching for subdomains of {domain}")
    results: Set[str] = set()
    
    async with aiohttp.ClientSession() as session:
        # Source 1 — crt.sh
        try:
            print("   Querying crt.sh...")
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            data = await fetch_json(session, url)
            
            if data and isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict) and "name_value" in entry:
                        name = entry["name_value"]
                        for sub in name.split("\n"):
                            sub = sub.strip()
                            if sub and domain in sub:
                                results.add(sub)
                print(f"   Found {len(results)} from crt.sh")
        except Exception as e:
            print(f"   Error with crt.sh: {e}")

        # Source 2 — HackerTarget
        try:
            print("   Querying HackerTarget...")
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            text = await fetch_text(session, url)
            
            if text:
                for line in text.splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip()
                        if sub and domain in sub:
                            results.add(sub)
                print(f"   Found subset from HackerTarget")
        except Exception as e:
            print(f"   Error with HackerTarget: {e}")

        # Source 3 — ThreatCrowd
        try:
            print("   Querying ThreatCrowd...")
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            data = await fetch_json(session, url)
            
            if data and isinstance(data, dict):
                for sub in data.get("subdomains", []):
                    if sub and domain in sub:
                        results.add(sub)
                print(f"   Found from ThreatCrowd")
        except Exception as e:
            print(f"   Error with ThreatCrowd: {e}")

    # Convert set to list for JSON serialization
    subdomains_list = list(results)
    print(f"[+] Total subdomains found: {len(subdomains_list)}")
    
    # Return JUST the list (not a dictionary)
    return subdomains_list

# Optional: Keep a sync version if needed elsewhere
def find_subdomains_sync(domain: str) -> Dict:
    """Sync version that returns dict with metadata"""
    import requests
    
    results = set()
    
    # Source 1 — crt.sh
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=15)
        for entry in r.json():
            name = entry["name_value"]
            for sub in name.split("\n"):
                if domain in sub:
                    results.add(sub.strip())
    except:
        pass

    # Source 2 — HackerTarget
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=10)
        for line in r.text.splitlines():
            sub = line.split(",")[0]
            results.add(sub)
    except:
        pass

    # Source 3 — ThreatCrowd
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        r = requests.get(url, timeout=10)
        data = r.json()
        for sub in data.get("subdomains", []):
            results.add(sub)
    except:
        pass

    return {
        "total_subdomains": len(results),
        "subdomains": list(results)
    }
