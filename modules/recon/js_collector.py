import aiohttp
import asyncio
from typing import List
import re

async def collect_js_files(domain: str) -> List[str]:
    """
    Collect JavaScript files from the target
    Returns a list of JS file URLs
    """
    print(f"[*] Collecting JS files for {domain}")
    js_files = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://{domain}", timeout=10, ssl=False) as response:
                html = await response.text()
                
                # Find script tags
                pattern = r'<script[^>]*src=["\'](.*?\.js[^"\']*)["\']'
                matches = re.findall(pattern, html, re.I)
                
                for match in matches:
                    if match.startswith('http'):
                        js_files.append(match)
                    elif match.startswith('//'):
                        js_files.append(f"https:{match}")
                    elif match.startswith('/'):
                        js_files.append(f"https://{domain}{match}")
                    else:
                        js_files.append(f"https://{domain}/{match}")
                
                print(f"[+] Found {len(js_files)} JS files")
                
    except Exception as e:
        print(f"[-] Error collecting JS files: {e}")
        js_files = [
            f"https://{domain}/static/js/main.js",
            f"https://{domain}/static/js/vendor.js"
        ]
    
    return js_files
