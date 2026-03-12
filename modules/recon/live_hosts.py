import aiohttp
import asyncio
from typing import List

async def check_live_hosts(hosts: List[str]) -> List[str]:
    """
    Check which hosts are live
    Returns a list of live hosts
    """
    print(f"[*] Checking live hosts: {hosts}")
    live_hosts = []
    
    async def check_host(host):
        try:
            # Try HTTP and HTTPS
            async with aiohttp.ClientSession() as session:
                for protocol in ['http', 'https']:
                    try:
                        url = f"{protocol}://{host}"
                        async with session.get(url, timeout=5, ssl=False) as response:
                            if response.status < 500:
                                return host
                    except:
                        continue
            return None
        except:
            return None
    
    # Check hosts concurrently
    tasks = [check_host(host) for host in hosts]
    results = await asyncio.gather(*tasks)
    
    # Filter out None results
    live_hosts = [host for host in results if host]
    
    print(f"[+] Found {len(live_hosts)} live hosts")
    return live_hosts
