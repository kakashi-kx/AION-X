"""
Bug Bounty Platform Integrations
Auto-submit findings to HackerOne, Bugcrowd, Intigriti, etc.
"""

import requests
import json
from typing import Dict, List, Any
import base64

class HackerOneIntegration:
    """HackerOne API Integration"""
    
    def __init__(self, username: str, api_key: str):
        self.username = username
        self.api_key = api_key
        self.base_url = "https://api.hackerone.com/v1"
        self.auth = base64.b64encode(f"{username}:{api_key}".encode()).decode()
        
    def create_report(self, vulnerability: Dict[str, Any], program: str) -> Dict:
        """Submit finding to HackerOne"""
        
        headers = {
            'Authorization': f'Basic {self.auth}',
            'Content-Type': 'application/json'
        }
        
        # Format according to HackerOne API
        report_data = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": vulnerability.get('name'),
                    "vulnerability_information": self._format_description(vulnerability),
                    "severity_rating": vulnerability.get('severity', 'medium').upper(),
                    "reporter": {
                        "username": self.username
                    }
                },
                "relationships": {
                    "program": {
                        "data": {
                            "type": "program",
                            "attributes": {
                                "handle": program
                            }
                        }
                    }
                }
            }
        }
        
        response = requests.post(
            f"{self.base_url}/reports",
            headers=headers,
            json=report_data
        )
        
        return response.json()
    
    def _format_description(self, vuln: Dict) -> str:
        """Format vulnerability for HackerOne"""
        return f"""
## Vulnerability Description
{vuln.get('description', 'No description')}

## Steps to Reproduce
1. Target: {vuln.get('affected_url')}
2. Payload: {vuln.get('proof_of_concept')}
3. Impact: {vuln.get('impact', 'See description')}

## Remediation
{vuln.get('remediation', 'No remediation provided')}

## Technical Details
- **CVSS Score**: {vuln.get('cvss_score', 'N/A')}
- **CWE**: {vuln.get('cwe', 'N/A')}
- **Confidence**: {vuln.get('confidence', 'High')}

## Additional Information
This finding was discovered by AION-X AI Security Platform.
        """

class BugcrowdIntegration:
    """Bugcrowd API Integration"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.bugcrowd.com/v4"
        
    def submit_finding(self, vulnerability: Dict, submission_id: str) -> Dict:
        """Submit finding to Bugcrowd"""
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            "data": {
                "type": "finding",
                "attributes": {
                    "title": vulnerability.get('name'),
                    "description": vulnerability.get('description'),
                    "severity": vulnerability.get('severity', 'p4').lower(),
                    "remediation": vulnerability.get('remediation'),
                    "proof_of_concept": vulnerability.get('proof_of_concept'),
                    "affected_resource": vulnerability.get('affected_url')
                },
                "relationships": {
                    "submission": {
                        "data": {
                            "type": "submission",
                            "id": submission_id
                        }
                    }
                }
            }
        }
        
        response = requests.post(
            f"{self.base_url}/findings",
            headers=headers,
            json=data
        )
        
        return response.json()

class IntigritiIntegration:
    """Intigriti API Integration"""
    
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://api.intigriti.com/external"
        self.token = self._get_token()
        
    def _get_token(self) -> str:
        """Get OAuth token"""
        response = requests.post(
            f"{self.base_url}/token",
            data={
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials'
            }
        )
        return response.json().get('access_token')
    
    def create_ticket(self, vulnerability: Dict, company_id: str) -> Dict:
        """Create ticket in Intigriti"""
        
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }
        
        data = {
            "title": vulnerability.get('name'),
            "description": vulnerability.get('description'),
            "type": "vulnerability",
            "severity": vulnerability.get('severity', 'medium'),
            "endpoint": vulnerability.get('affected_url'),
            "proofOfConcept": vulnerability.get('proof_of_concept'),
            "remediation": vulnerability.get('remediation'),
            "companyId": company_id
        }
        
        response = requests.post(
            f"{self.base_url}/tickets",
            headers=headers,
            json=data
        )
        
        return response.json()

class AutoSubmitter:
    """Auto-submit findings to multiple platforms"""
    
    def __init__(self, config: Dict):
        self.platforms = {}
        
        if 'hackerone' in config:
            self.platforms['hackerone'] = HackerOneIntegration(
                config['hackerone']['username'],
                config['hackerone']['api_key']
            )
            
        if 'bugcrowd' in config:
            self.platforms['bugcrowd'] = BugcrowdIntegration(
                config['bugcrowd']['token']
            )
            
        if 'intigriti' in config:
            self.platforms['intigriti'] = IntigritiIntegration(
                config['intigriti']['client_id'],
                config['intigriti']['client_secret']
            )
    
    async def submit_finding(self, vulnerability: Dict, platform_config: Dict) -> Dict:
        """Submit finding to specified platform"""
        platform = platform_config.get('platform')
        program = platform_config.get('program')
        
        if platform == 'hackerone' and 'hackerone' in self.platforms:
            return self.platforms['hackerone'].create_report(vulnerability, program)
        elif platform == 'bugcrowd' and 'bugcrowd' in self.platforms:
            return self.platforms['bugcrowd'].submit_finding(vulnerability, program)
        elif platform == 'intigriti' and 'intigriti' in self.platforms:
            return self.platforms['intigriti'].create_ticket(vulnerability, program)
        else:
            return {"error": "Platform not configured"}
    
    async def submit_all(self, vulnerabilities: List[Dict], config: Dict) -> List[Dict]:
        """Submit all findings to configured platforms"""
        results = []
        
        for vuln in vulnerabilities:
            for platform_config in config.get('platforms', []):
                result = await self.submit_finding(vuln, platform_config)
                results.append({
                    'vulnerability': vuln.get('name'),
                    'platform': platform_config.get('platform'),
                    'result': result
                })
                
        return results

# Example configuration
CONFIG = {
    "platforms": [
        {
            "platform": "hackerone",
            "program": "example_program",
            "auto_submit": True,
            "min_severity": "Medium"
        },
        {
            "platform": "bugcrowd",
            "program": "submission_id_123",
            "auto_submit": False,
            "min_severity": "High"
        }
    ],
    "hackerone": {
        "username": "your_username",
        "api_key": "your_api_key"
    },
    "bugcrowd": {
        "token": "your_token"
    }
}
