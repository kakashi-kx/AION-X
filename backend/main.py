from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict
import uuid
import json
from datetime import datetime
import os

# Import your modules
from modules.recon.recon_engine import run_full_recon
from modules.recon.subdomain_scanner import find_subdomains
from modules.recon.wayback_urls import get_wayback_urls
from modules.recon.otx_urls import get_otx_urls
from modules.recon.live_hosts import check_live_hosts
from modules.recon.param_discovery import find_parameters
from modules.recon.dir_finder import find_directories
from modules.recon.tech_detector import detect_tech

app = FastAPI(title="AION-X API", version="0.1.0")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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

# In-memory storage (replace with database in production)
active_scans = {}
scan_results = {}

# Endpoints
@app.get("/")
async def root():
    return {"message": "AION-X API is running", "version": "0.1.0"}

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    # TODO: Implement actual stats from database
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
    try:
        # Run recon modules
        results = {
            "target": request.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": await find_subdomains(request.target),
            "urls": await get_wayback_urls(request.target),
            "otx_urls": await get_otx_urls(request.target),
            "live_hosts": await check_live_hosts([request.target]),
            "parameters": await find_parameters(request.target),
            "directories": await find_directories(request.target),
            "technologies": await detect_tech(request.target)
        }
        
        # Store results
        scan_id = str(uuid.uuid4())
        scan_results[scan_id] = results
        
        return JSONResponse(content=results)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a vulnerability scan"""
    scan_id = str(uuid.uuid4())
    
    # Initialize scan status
    active_scans[scan_id] = {
        "status": "starting",
        "progress": 0,
        "target": request.target,
        "scan_type": request.scan_type
    }
    
    # Run scan in background
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
    # TODO: Implement export functionality
    # For now, return sample data
    data = {"type": scan_type, "results": [], "exported_at": datetime.now().isoformat()}
    
    # Save to temp file
    filename = f"export_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = f"/tmp/{filename}"
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    return FileResponse(filepath, filename=filename, media_type="application/json")

# Background task for vulnerability scanning
async def run_vulnerability_scan(scan_id: str, request: ScanRequest):
    """Run vulnerability scan in background"""
    try:
        # Update status
        active_scans[scan_id]["status"] = "scanning"
        
        # TODO: Implement actual vulnerability scanning logic
        # This is a placeholder that simulates scanning progress
        import asyncio
        
        for i in range(1, 11):
            await asyncio.sleep(2)  # Simulate work
            active_scans[scan_id]["progress"] = i * 10
            active_scans[scan_id]["status"] = f"Scanning... {i*10}%"
        
        # Simulate findings
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
        
        # Store results
        scan_results[scan_id] = {
            "target": request.target,
            "scan_type": request.scan_type,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities
        }
        
        # Remove from active scans
        del active_scans[scan_id]
        
    except Exception as e:
        active_scans[scan_id]["status"] = f"failed: {str(e)}"
        active_scans[scan_id]["progress"] = 0

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
