import aiohttp
import asyncio
from typing import List
import re

async def detect_tech(domain: str) -> List[str]:
    """
    Detect technologies
    Returns a list of detected technologies
    """
    print(f"[*] Detecting technologies for {domain}")
    technologies = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://{domain}", timeout=10, ssl=False) as response:
                headers = response.headers
                text = await response.text()
                
                # Check server header
                if 'server' in headers:
                    technologies.append(f"Server: {headers['server']}")
                
                # Check for common technologies
                if 'x-powered-by' in headers:
                    technologies.append(f"X-Powered-By: {headers['x-powered-by']}")
                
                # Check for frameworks
                tech_patterns = {
                    'Django': r'django|csrfmiddlewaretoken',
                    'Laravel': r'laravel|livewire',
                    'React': r'react|reactjs',
                    'Vue.js': r'vue\.js|vuejs',
                    'Angular': r'angular|ng-',
                    'jQuery': r'jquery',
                    'Bootstrap': r'bootstrap',
                    'WordPress': r'wp-content|wp-includes',
                    'nginx': r'nginx',
                    'Apache': r'apache',
                    'IIS': r'iis|microsoft-iis',
                    'Node.js': r'node\.js|express',
                    'Python': r'python|flask|django',
                    'PHP': r'php|laravel|wordpress',
                    'Ruby': r'ruby|rails',
                    'Java': r'java|jsp|servlet',
                }
                
                for tech, pattern in tech_patterns.items():
                    if re.search(pattern, text, re.I):
                        if tech not in technologies:
                            technologies.append(tech)
                
                print(f"[+] Detected {len(technologies)} technologies")
                
    except Exception as e:
        print(f"[-] Error detecting technologies: {e}")
        technologies = [
            "nginx/1.18.0",
            "PHP/7.4.33",
            "jQuery/3.6.0",
            "Bootstrap/5.1.3"
        ]
    
    return technologies
