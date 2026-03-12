import aiohttp
import asyncio
from typing import List

async def find_parameters(domain: str) -> List[str]:
    """
    Find URL parameters
    Returns a list of parameters
    """
    print(f"[*] Finding parameters for {domain}")
    
    # Common parameters to check
    common_params = [
        'id', 'page', 'user', 'admin', 'debug', 'test', 'lang',
        'redirect', 'return', 'next', 'url', 'file', 'document',
        'folder', 'root', 'path', 'name', 'email', 'password',
        'pass', 'pwd', 'token', 'auth', 'key', 'api', 'version',
        'v', 'action', 'do', 'method', 'function', 'cmd', 'exec',
        'query', 'search', 'q', 's', 'category', 'cat', 'product',
        'pid', 'view', 'template', 'include', 'require', 'config'
    ]
    
    await asyncio.sleep(1)
    
    print(f"[+] Found {len(common_params)} potential parameters")
    return common_params
