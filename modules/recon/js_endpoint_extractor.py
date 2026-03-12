import aiohttp
import asyncio
from typing import List
import re

async def extract_endpoints_from_js(js_url: str) -> List[str]:
    """
    Extract API endpoints from JavaScript files
    Returns a list of endpoints
    """
    print(f"[*] Extracting endpoints from {js_url}")
    endpoints = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(js_url, timeout=10, ssl=False) as response:
                js_content = await response.text()
                
                # Look for API endpoint patterns
                patterns = [
                    r'["\'](/api/[^"\']*)["\']',
                    r'["\'](/v[0-9]/[^"\']*)["\']',
                    r'["\'](/rest/[^"\']*)["\']',
                    r'["\'](/graphql[^"\']*)["\']',
                    r'["\'](/wp-json/[^"\']*)["\']',
                    r'url:\s*["\']([^"\']*)["\']',
                    r'fetch\(["\']([^"\']*)["\']',
                    r'axios\.\w+\(["\']([^"\']*)["\']',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, js_content)
                    endpoints.extend(matches)
                
                # Remove duplicates
                endpoints = list(set(endpoints))
                
    except Exception as e:
        print(f"[-] Error extracting endpoints: {e}")
    
    print(f"[+] Found {len(endpoints)} endpoints in {js_url}")
    return endpoints
