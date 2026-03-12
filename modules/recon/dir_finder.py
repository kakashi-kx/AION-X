import aiohttp
import asyncio
from typing import List

async def find_directories(domain: str) -> List[str]:
    """
    Find directories
    Returns a list of directories
    """
    print(f"[*] Finding directories for {domain}")
    
    # Common directories to check
    common_dirs = [
        '/admin', '/administrator', '/backup', '/backups', '/bak',
        '/css', '/js', '/images', '/img', '/assets', '/static',
        '/uploads', '/download', '/files', '/media', '/docs',
        '/api', '/v1', '/v2', '/rest', '/graphql', '/swagger',
        '/wp-admin', '/wp-content', '/wp-includes', '/wordpress',
        '/phpmyadmin', '/pma', '/myadmin', '/mysql', '/database',
        '/git', '/.git', '/svn', '/.svn', '/env', '/.env',
        '/config', '/configuration', '/settings', '/setup',
        '/install', '/installer', '/license', '/readme', '/README',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
        '/.well-known', '/server-status', '/server-info'
    ]
    
    found_dirs = []
    
    async def check_directory(dir_path):
        try:
            url = f"https://{domain}{dir_path}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5, ssl=False) as response:
                    if response.status != 404:
                        return dir_path
            return None
        except:
            return None
    
    # Check directories concurrently
    tasks = [check_directory(dir_path) for dir_path in common_dirs[:20]]
    results = await asyncio.gather(*tasks)
    
    # Filter out None results
    found_dirs = [d for d in results if d]
    
    print(f"[+] Found {len(found_dirs)} directories")
    return found_dirs
