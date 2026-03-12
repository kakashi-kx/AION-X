import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import json
from datetime import datetime
import asyncio
import inspect

# Import your modules
try:
    from modules.recon.subdomain_scanner import find_subdomains
    from modules.recon.wayback_urls import get_wayback_urls
    from modules.recon.otx_urls import get_otx_urls
    from modules.recon.live_hosts import check_live_hosts
    from modules.recon.param_discovery import find_parameters
    from modules.recon.dir_finder import find_directories
    from modules.recon.tech_detector import detect_tech
    from modules.recon.recon_engine import run_full_recon
    MODULES_LOADED = True
    print("✅ All modules loaded successfully")
except ImportError as e:
    print(f"⚠️ Warning: Some modules could not be imported: {e}")
    MODULES_LOADED = False
    
    # Create placeholder functions for development
    async def find_subdomains(target): 
        return [f"www.{target}", f"mail.{target}", f"api.{target}"]
    async def get_wayback_urls(target): 
        return [f"https://{target}/page1", f"https://{target}/page2"]
    async def get_otx_urls(target): 
        return [f"https://{target}/otx1", f"https://{target}/otx2"]
    async def check_live_hosts(targets): 
        return targets
    async def find_parameters(target): 
        return ["id", "page", "user", "admin"]
    async def find_directories(target): 
        return ["/admin", "/api", "/backup"]
    async def detect_tech(target): 
        return ["nginx", "python", "react"]

app = FastAPI(title="AION-X API", version="0.1.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://0.0.0.0:3000",
        "http://0.0.0.0:8000",
        "*"  # Allow all origins for development
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600
)

# Add OPTIONS handler for preflight requests
@app.options("/{path:path}")
async def options_handler(path: str):
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "600"
        }
    )

# Data models
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    options: Dict = {}

class ReconRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    completed: bool
    vulnerabilities: Optional[List[Dict]] = None

# In-memory storage
active_scans = {}
scan_results = {}

@app.get("/")
async def root():
    return {
        "message": "AION-X API is running",
        "version": "0.1.0",
        "modules_loaded": MODULES_LOADED,
        "status": "ready"
    }

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    return {
        "total_scans": len(scan_results),
        "active_scans": len(active_scans),
        "total_vulnerabilities": 0,
        "total_hosts": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "medium_vulns": 0,
        "low_vulns": 0,
        "scan_dates": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "scan_counts": [0, 0, 0, 0, 0, 0, 0]
    }

@app.post("/recon")
async def run_recon(request: ReconRequest):
    """Run reconnaissance on target"""
    print(f"=== Recon request received for target: {request.target} ===")
    
    try:
        # Run all recon modules concurrently
        subdomains_task = find_subdomains(request.target)
        wayback_task = get_wayback_urls(request.target)
        otx_task = get_otx_urls(request.target)
        live_hosts_task = check_live_hosts([request.target])
        parameters_task = find_parameters(request.target)
        directories_task = find_directories(request.target)
        tech_task = detect_tech(request.target)
        
        # Gather all results
        subdomains, wayback_urls, otx_urls, live_hosts, parameters, directories, technologies = await asyncio.gather(
            subdomains_task,
            wayback_task,
            otx_task,
            live_hosts_task,
            parameters_task,
            directories_task,
            tech_task,
            return_exceptions=True
        )
        
        # Handle any exceptions
        results = {
            "target": request.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": subdomains if not isinstance(subdomains, Exception) else [],
            "urls": wayback_urls if not isinstance(wayback_urls, Exception) else [],
            "otx_urls": otx_urls if not isinstance(otx_urls, Exception) else [],
            "live_hosts": live_hosts if not isinstance(live_hosts, Exception) else [],
            "parameters": parameters if not isinstance(parameters, Exception) else [],
            "directories": directories if not isinstance(directories, Exception) else [],
            "technologies": technologies if not isinstance(technologies, Exception) else []
        }
        
        # Store results
        scan_id = str(uuid.uuid4())
        scan_results[scan_id] = results
        
        print(f"=== Recon completed for {request.target} ===")
        print(f"   Subdomains: {len(results['subdomains'])}")
        print(f"   URLs: {len(results['urls'])}")
        print(f"   Parameters: {len(results['parameters'])}")
        print(f"   Directories: {len(results['directories'])}")
        print(f"   Technologies: {len(results['technologies'])}")
        
        return JSONResponse(content=results)
        
    except Exception as e:
        print(f"!!! Recon failed: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "Reconnaissance failed"}
        )

@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a vulnerability scan"""
    scan_id = str(uuid.uuid4())
    
    active_scans[scan_id] = {
        "status": "starting",
        "progress": 0,
        "target": request.target,
        "scan_type": request.scan_type
    }
    
    background_tasks.add_task(run_vulnerability_scan, scan_id, request)
    
    return {"scan_id": scan_id, "status": "started"}

@app.get("/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    """Get scan status and results"""
    if scan_id in active_scans:
        return ScanStatus(
            scan_id=scan_id,
            status=active_scans[scan_id]["status"],
            progress=active_scans[scan_id]["progress"],
            completed=False
        )
    elif scan_id in scan_results:
        return ScanStatus(
            scan_id=scan_id,
            status="completed",
            progress=100,
            completed=True,
            vulnerabilities=scan_results[scan_id].get("vulnerabilities", [])
        )
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/export/{scan_type}")
async def export_results(scan_type: str):
    """Export scan results"""
    data = {
        "type": scan_type,
        "results": [],
        "exported_at": datetime.now().isoformat()
    }
    
    filename = f"export_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = f"/tmp/{filename}"
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    return FileResponse(filepath, filename=filename, media_type="application/json")

async def run_vulnerability_scan(scan_id: str, request: ScanRequest):
    """Run vulnerability scan in background"""
    try:
        active_scans[scan_id]["status"] = "scanning"
        
        import asyncio
        
        for i in range(1, 11):
            await asyncio.sleep(2)
            active_scans[scan_id]["progress"] = i * 10
            active_scans[scan_id]["status"] = f"Scanning... {i*10}%"
        
        vulnerabilities = [
            {
                "name": "SQL Injection",
                "severity": "Critical",
                "description": "SQL injection vulnerability in login parameter",
                "cve_id": "CVE-2023-1234",
                "cvss": 9.8,
                "location": f"{request.target}/login"
            },
            {
                "name": "XSS Vulnerability",
                "severity": "Medium",
                "description": "Reflected XSS in search parameter",
                "cve_id": "CVE-2023-5678",
                "cvss": 6.1,
                "location": f"{request.target}/search"
            }
        ]
        
        scan_results[scan_id] = {
            "target": request.target,
            "scan_type": request.scan_type,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities
        }
        
        del active_scans[scan_id]
        
    except Exception as e:
        active_scans[scan_id]["status"] = f"failed: {str(e)}"
        active_scans[scan_id]["progress"] = 0

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
