"""
Reconnaissance Modules Package
Provides various reconnaissance and information gathering capabilities
"""

from .subdomain_scanner import find_subdomains
from .wayback_urls import get_wayback_urls
from .otx_urls import get_otx_urls
from .live_hosts import check_live_hosts
from .param_discovery import find_parameters
from .dir_finder import find_directories
from .tech_detector import detect_tech
from .http_mapper import map_http_services
from .js_collector import collect_js_files
from .js_endpoint_extractor import extract_endpoints_from_js
from .recon_engine import run_full_recon

__all__ = [
    # Core reconnaissance functions
    'find_subdomains',
    'get_wayback_urls',
    'get_otx_urls',
    'check_live_hosts',
    'find_parameters',
    'find_directories',
    'detect_tech',
    'map_http_services',
    'collect_js_files',
    'extract_endpoints_from_js',
    'run_full_recon'
]

__version__ = "0.1.0"
__author__ = "Kakashi"

# Module description
__description__ = """
Reconnaissance Module - Information Gathering Suite
---------------------------------------------------
This module provides comprehensive reconnaissance capabilities:
- Subdomain enumeration
- URL discovery (Wayback Machine & OTX)
- Live host detection
- Parameter discovery
- Directory brute-forcing
- Technology stack detection
- HTTP service mapping
- JavaScript file collection and analysis
- API endpoint extraction
"""
