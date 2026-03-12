"""
OWASP API Security Top 10 (2026) Scanner
Implements automated testing for all API security categories
"""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import hashlib
import re

@dataclass
class APIVulnerability:
    category: str  # API1-API10
    name: str
    severity: str
    description: str
    affected_endpoint: str
    proof_of_concept: str
    remediation: str

class OWASPAPIScanner:
    def __init__(self, target: str, api_base: str = "/api"):
        self.target = target
        self.api_base = api_base
        self.session = None
        self.findings: List[APIVulnerability] = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    async def discover_endpoints(self) -> List[str]:
        """Discover API endpoints using various techniques"""
        endpoints = []
        
        # Common API paths
        common_paths = [
            "/api",
            "/v1", "/v2", "/v3",
            "/graphql",
            "/rest",
            "/swagger", "/swagger.json", "/swagger-ui",
            "/openapi.json",
            "/docs",
            "/api-docs",
            "/api/v1", "/api/v2",
            "/api/users",
            "/api/auth",
            "/api/login",
            "/api/register",
            "/api/admin",
            "/api/health",
            "/api/status"
        ]
        
        for path in common_paths:
            url = f"https://{self.target}{path}"
            try:
                async with self.session.get(url) as resp:
                    if resp.status != 404:
                        endpoints.append(path)
                        print(f"✅ Discovered endpoint: {path}")
            except:
                continue
                
        # Try to parse from known documentation
        await self._discover_from_swagger(endpoints)
        
        return endpoints
    
    async def _discover_from_swagger(self, endpoints: List[str]):
        """Try to discover endpoints from Swagger/OpenAPI"""
        swagger_paths = [
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/api/swagger.json",
            "/swagger/docs/v1",
            "/swagger-ui.html",
            "/api-docs",
            "/v2/api-docs",
            "/v3/api-docs",
            "/openapi.json"
        ]
        
        for path in swagger_paths:
            url = f"https://{self.target}{path}"
            try:
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        # Parse OpenAPI/Swagger
                        if "paths" in data:
                            for path in data["paths"].keys():
                                endpoints.append(path)
                                print(f"✅ Discovered from Swagger: {path}")
                        break
            except:
                continue
    
    async def scan_all(self) -> List[APIVulnerability]:
        """Run all OWASP API Top 10 checks"""
        endpoints = await self.discover_endpoints()
        
        tasks = [
            self.check_api1_bola(endpoints),
            self.check_api2_broken_auth(endpoints),
            self.check_api3_bopla(endpoints),
            self.check_api4_unrestricted_resource(endpoints),
            self.check_api5_broken_function_level_auth(endpoints),
            self.check_api6_unrestricted_business_flows(endpoints),
            self.check_api7_security_misconfiguration(endpoints),
            self.check_api8_injection(endpoints),
            self.check_api9_improper_asset_management(endpoints),
            self.check_api10_unsafe_consumption(endpoints)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"Error in API scan: {result}")
            elif result:
                self.findings.extend(result)
                
        return self.findings
    
    async def check_api1_bola(self, endpoints: List[str]) -> List[APIVulnerability]:
        """API1:2026 - Broken Object Level Authorization (BOLA)"""
        findings = []
        
        # Pattern: /api/resource/{id}
        pattern = re.compile(r'/(?:api|v\d+)/([^/]+)/(\d+)')
        
        for endpoint in endpoints:
            match = pattern.search(endpoint)
            if match:
                resource, obj_id = match.groups()
                
                # Test with sequential IDs
                test_ids = [1, 2, 100, 999, obj_id]
                
                for test_id in test_ids:
                    if str(test_id) != obj_id:
                        test_endpoint = endpoint.replace(obj_id, str(test_id))
                        url = f"https://{self.target}{test_endpoint}"
                        
                        try:
                            # Try with different HTTP methods
                            async with self.session.get(url) as resp:
                                if resp.status == 200:
                                    # Check if we got data for a different object
                                    findings.append(APIVulnerability(
                                        category="API1:2026",
                                        name="Broken Object Level Authorization (BOLA)",
                                        severity="Critical",
                                        description=f"Access to {resource} object {test_id} returned 200 OK without proper authorization",
                                        affected_endpoint=test_endpoint,
                                        proof_of_concept=f"GET {test_endpoint} returned data for object owned by another user",
                                        remediation="Implement proper access control checks for every object access"
                                    ))
                                    break
                        except:
                            continue
                            
        return findings
    
    async def check_api2_broken_auth(self, endpoints: List[str]) -> List[APIVulnerability]:
        """API2:2026 - Broken Authentication"""
        findings = []
        
        auth_endpoints = [e for e in endpoints if 'login' in e or 'auth' in e or 'token' in e]
        
        for endpoint in auth_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            # Test for weak password policy
            weak_creds = [
                {"username": "admin", "password": "admin"},
                {"username": "admin", "password": "password"},
                {"username": "admin", "password": "123456"},
                {"username": "admin", "password": "admin123"},
                {"username": "test", "password": "test"}
            ]
            
            for creds in weak_creds:
                try:
                    async with self.session.post(url, json=creds) as resp:
                        if resp.status == 200:
                            findings.append(APIVulnerability(
                                category="API2:2026",
                                name="Broken Authentication - Weak Credentials",
                                severity="High",
                                description=f"Authentication successful with weak credentials: {creds}",
                                affected_endpoint=endpoint,
                                proof_of_concept=f"POST {endpoint} with {creds} returned 200 OK",
                                remediation="Implement strong password policy and rate limiting"
                            ))
                            break
                except:
                    continue
            
            # Test for JWT weaknesses
            try:
                # First, get a valid token
                async with self.session.post(url, json={"username": "admin", "password": "admin"}) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        token = data.get('token') or data.get('access_token')
                        
                        if token:
                            # Test token validation
                            parts = token.split('.')
                            if len(parts) == 3:
                                # Check for 'none' algorithm
                                import base64
                                header = json.loads(base64.b64decode(parts[0] + '==').decode())
                                if header.get('alg') == 'none':
                                    findings.append(APIVulnerability(
                                        category="API2:2026",
                                        name="Broken Authentication - JWT 'none' Algorithm",
                                        severity="Critical",
                                        description="JWT token uses 'none' algorithm, allowing signature bypass",
                                        affected_endpoint=endpoint,
                                        proof_of_concept=f"Token uses 'none' algorithm",
                                        remediation="Always verify JWT signatures and disallow 'none' algorithm"
                                    ))
            except:
                pass
                
        return findings
    
    async def check_api3_bopla(self, endpoints: List[str]) -> List[APIVulnerability]:
        """API3:2026 - Broken Object Property Level Authorization (BOPLA)"""
        findings = []
        
        # Test for mass assignment
        update_endpoints = [e for e in endpoints if 'update' in e or 'profile' in e or 'user' in e]
        
        for endpoint in update_endpoints:
            url = f"https://{self.target}{endpoint}"
            
            # Try to update sensitive fields
            test_payloads = [
                {"role": "admin"},
                {"is_admin": True},
                {"permissions": ["*"]},
                {"email": "attacker@evil.com"},
                {"password": "hacked123"},
                {"verified": True},
                {"balance": 999999}
            ]
            
            for payload in test_payloads:
                try:
                    async with self.session.put(url, json=payload) as resp:
                        if resp.status == 200:
                            findings.append(APIVulnerability(
                                category="API3:2026",
                                name="Broken Object Property Level Authorization (BOPLA)",
                                severity="High",
                                description=f"Mass assignment allowed for sensitive field: {list(payload.keys())[0]}",
                                affected_endpoint=endpoint,
                                proof_of_concept=f"PUT {endpoint} with {payload} returned 200 OK",
                                remediation="Implement allowlist for updatable fields and validate user permissions per field"
                            ))
                            break
                except:
                    continue
                    
        return findings
    
    async def check_api6_unrestricted_business_flows(self, endpoints: List[str]) -> List[APIVulnerability]:
        """API6:2026 - Unrestricted Access to Sensitive Business Flows"""
        findings = []
        
        # Test for rate limiting and automation detection
        sensitive_flows = [
            "/api/login",
            "/api/register",
            "/api/forgot-password",
            "/api/reset-password",
            "/api/checkout",
            "/api/order",
            "/api/payment",
            "/api/transfer"
        ]
        
        for flow in sensitive_flows:
            matching_endpoints = [e for e in endpoints if flow in e]
            
            for endpoint in matching_endpoints:
                url = f"https://{self.target}{endpoint}"
                
                # Test rate limiting with rapid requests
                success_count = 0
                for i in range(10):
                    try:
                        async with self.session.post(url, json={"test": i}) as resp:
                            if resp.status < 400:  # Any success or redirect
                                success_count += 1
                    except:
                        continue
                
                if success_count > 8:  # Most requests succeeded
                    findings.append(APIVulnerability(
                        category="API6:2026",
                        name="Unrestricted Access to Sensitive Business Flows",
                        severity="Medium",
                        description=f"No rate limiting detected on sensitive endpoint {endpoint}",
                        affected_endpoint=endpoint,
                        proof_of_concept=f"10 rapid requests to {endpoint}: {success_count} succeeded",
                        remediation="Implement rate limiting and CAPTCHA for sensitive operations"
                    ))
                
                # Test for missing automation detection
                try:
                    # Try with automation-like headers
                    headers = {
                        'User-Agent': 'python-requests/2.31.0',
                        'X-Automated-Tool': 'true'
                    }
                    async with self.session.post(url, json={}, headers=headers) as resp:
                        if resp.status < 400:
                            findings.append(APIVulnerability(
                                category="API6:2026",
                                name="Missing Automation Detection",
                                severity="Medium",
                                description=f"No bot detection on {endpoint}",
                                affected_endpoint=endpoint,
                                proof_of_concept=f"Request with automation headers succeeded",
                                remediation="Implement bot detection and CAPTCHA challenges"
                            ))
                except:
                    continue
                    
        return findings
    
    async def check_api7_security_misconfiguration(self, endpoints: List[str]) -> List[APIVulnerability]:
        """API7:2026 - Security Misconfiguration"""
        findings = []
        
        for endpoint in endpoints[:5]:  # Check first few endpoints
            url = f"https://{self.target}{endpoint}"
            
            try:
                async with self.session.options(url) as resp:
                    # Check CORS
                    allow_origin = resp.headers.get('Access-Control-Allow-Origin')
                    if allow_origin == '*':
                        findings.append(APIVulnerability(
                            category="API7:2026",
                            name="Security Misconfiguration - Wildcard CORS",
                            severity="Medium",
                            description="API allows wildcard CORS, potentially exposing data to any origin",
                            affected_endpoint=endpoint,
                            proof_of_concept=f"OPTIONS {endpoint} returned Access-Control-Allow-Origin: *",
                            remediation="Restrict CORS to trusted origins only"
                        ))
                    
                    # Check for verbose error messages
                    async with self.session.get(url + "'") as err_resp:  # Add SQL injection attempt
                        if err_resp.status == 500:
                            text = await err_resp.text()
                            if "SQL" in text or "syntax" in text or "exception" in text:
                                findings.append(APIVulnerability(
                                    category="API7:2026",
                                    name="Security Misconfiguration - Verbose Errors",
                                    severity="Low",
                                    description="API returns verbose error messages with debugging information",
                                    affected_end
