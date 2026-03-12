import aiohttp
import asyncio
from typing import List, Dict

async def map_http_services(domain: str) -> Dict:
    """
    Map HTTP services
    Returns a dictionary of HTTP services
    """
    print(f"[*] Mapping HTTP services for {domain}")
    
    services = {
        "http": False,
        "https": False,
        "redirects": [],
        "headers": {}
    }
    
    try:
        # Check HTTP
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(f"http://{domain}", timeout=5) as resp:
                    services["http"] = True
                    services["headers"]["http"] = dict(resp.headers)
                    if resp.status in [301, 302]:
                        services["redirects"].append({
                            "from": "http",
                            "to": resp.headers.get('location', '')
                        })
            except:
                pass
            
            # Check HTTPS
            try:
                async with session.get(f"https://{domain}", timeout=5, ssl=False) as resp:
                    services["https"] = True
                    services["headers"]["https"] = dict(resp.headers)
            except:
                pass
                
    except Exception as e:
        print(f"[-] Error mapping HTTP services: {e}")
    
    return services
