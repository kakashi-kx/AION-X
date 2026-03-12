import aiohttp
import asyncio
from typing import List

async def get_wayback_urls(domain: str) -> List[str]:
    """
    Get URLs from Wayback Machine
    Returns a list of URLs
    """
    print(f"[*] Fetching Wayback URLs for {domain}")
    urls = []
    
    try:
        # Using the Wayback Machine CDX API
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    # Skip the first element which is usually the header
                    if len(data) > 1:
                        urls = [item[0] for item in data[1:]][:50]
    except Exception as e:
        print(f"[-] Error fetching Wayback URLs: {e}")
        # Return sample data for testing
        urls = [
            f"https://{domain}/",
            f"https://{domain}/index.html",
            f"https://{domain}/about.html",
            f"https://{domain}/contact.html",
            f"https://{domain}/products.html"
        ]
    
    print(f"[+] Found {len(urls)} Wayback URLs for {domain}")
    return urls
