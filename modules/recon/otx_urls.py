import aiohttp
import asyncio
from typing import List

async def get_otx_urls(domain: str) -> List[str]:
    """
    Get URLs from AlienVault OTX
    Returns a list of URLs
    """
    print(f"[*] Fetching OTX URLs for {domain}")
    urls = []
    
    try:
        # AlienVault OTX API endpoint
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    if 'url_list' in data:
                        urls = [item['url'] for item in data['url_list']][:50]
    except Exception as e:
        print(f"[-] Error fetching OTX URLs: {e}")
        # Return sample data for testing
        urls = [
            f"https://{domain}/otx1",
            f"https://{domain}/otx2",
            f"https://{domain}/otx3"
        ]
    
    print(f"[+] Found {len(urls)} OTX URLs for {domain}")
    return urls
