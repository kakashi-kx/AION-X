import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import uuid
import json
from datetime import datetime
import asyncio
import inspect

# ==================== MODULE IMPORTS ====================

# Reconnaissance Modules (Working)
try:
    from modules.recon.subdomain_scanner import find_subdomains
    from modules.recon.wayback_urls import get_wayback_urls
    from modules.recon.otx_urls import get_otx_urls
    from modules.recon.live_hosts import check_live_hosts
    from modules.recon.param_discovery import find_parameters
    from modules.recon.dir_finder import find_directories
    from modules.recon.tech_detector import detect_tech
    from modules.recon.recon_engine import run_full_recon
    RECON_MODULES_LOADED = True
    print("✅ Recon modules loaded successfully")
except ImportError as e:
    print(f"⚠️ Warning: Recon modules could not be imported: {e}")
    RECON_MODULES_LOADED = False
    
    # Create placeholder functions
    async def find_subdomains(target): return [f"www.{target}"]
    async def get_wayback_urls(target): return []
    async def get_otx_urls(target): return []
    async def check_live_hosts(targets): return targets
    async def find_parameters(target): return ["id", "page"]
    async def find_directories(target): return ["/admin"]
    async def detect_tech(target): return ["nginx"]

# Advanced AI Modules (New)
try:
    from modules.ai.bugreaper import BugReaperEngine
    from modules.api.owasp_api_scanner import OWASPAPIScanner
    from modules.devsecops.cicd_scanner import CICDScanner
    from modules.integrations.bugbounty_platforms import AutoSubmitter
    from modules.reporting.ai_report_generator import AIReportGenerator
    AI_MODULES_LOADED = True
    print("✅ Advanced AI modules loaded successfully")
except ImportError as e:
    print(f"⚠️ Warning: Advanced AI modules could not be imported: {e}")
    AI_MODULES_LOADED = False

# ==================== FASTAPI SETUP ====================

app = FastAPI(
    title="AION-X AI Penetration Testing Platform",
    version="3.0.0",
    description="Complete AI-Powered Security Testing Platform with Recon, API Testing, CI/CD Scanning, and Bug Bounty Integration"
)

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
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=600
)

# OPTIONS handler
@app.options("/{path:path}")
async def options_handler(path: str):
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
    )

# ==================== DATA MODELS ====================

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    options: Dict = {}

class ReconRequest(BaseModel):
    target: str
    modules: Optional[List[str]] = None

class AIScanRequest(BaseModel):
    target: str
    scan_depth: str = "standard"

class APIScanRequest(BaseModel):
    target: str
    api_base: str = "/api"

class CICDScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    token: Optional[str] = None

class ReportRequest(BaseModel):
    format: str = "html"
    include_ai_analysis: bool = True

class BugBountySubmission(BaseModel):
    vulnerability: Dict[str, Any]
    platform: str
    program_id: str

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    completed: bool
    vulnerabilities: Optional[List[Dict]] = None

# ==================== STORAGE ====================

active_scans = {}
scan_results = {}

# ==================== ROOT ENDPOINT ====================

@app.get("/")
async def root():
    return {
        "message": "AION-X AI Penetration Testing Platform",
        "version": "3.0.0",
        "status": "ready",
        "features": {
            "reconnaissance": RECON_MODULES_LOADED,
            "ai_bugreaper": AI_MODULES_LOADED,
            "api_scanner": AI_MODULES_LOADED,
            "cicd_scanner": AI_MODULES_LOADED,
            "reporting": AI_MODULES_LOADED,
            "bugbounty_integration": AI_MODULES_LOADED
        }
    }

# ==================== STATS ENDPOINT ====================

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    total_vulns = 0
    critical = high = medium = low = 0
    
    for scan in scan_results.values():
        vulns = scan.get("vulnerabilities", []) or scan.get("findings", [])
        total_vulns += len(vulns)
        for v in vulns:
            severity = v.get("severity", "").lower()
            if "critical" in severity:
                critical += 1
            elif "high" in severity:
                high += 1
            elif "medium" in severity:
                medium += 1
            else:
                low += 1
    
    return {
        "total_scans": len(scan_results),
        "active_scans": len(active_scans),
        "total_vulnerabilities": total_vulns,
        "total_hosts": len(set(s.get("target") for s in scan_results.values())),
        "critical_vulns": critical,
        "high_vulns": high,
        "medium_vulns": medium,
        "low_vulns": low,
        "scan_dates": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "scan_counts": [0, 0, 0, 0, 0, 0, 0]
    }

# ==================== RECONNAISSANCE ENDPOINT (WORKING) ====================

@app.post("/recon")
async def run_recon(request: ReconRequest):
    """Run reconnaissance on target"""
    print(f"=== Recon started for: {request.target} ===")
    
    try:
        timeout = 30
        results = {
            "target": request.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "urls": [],
            "otx_urls": [],
            "live_hosts": [],
            "parameters": [],
            "directories": [],
            "technologies": []
        }
        
        modules = [
            ("subdomains", find_subdomains, [request.target]),
            ("urls", get_wayback_urls, [request.target]),
            ("otx_urls", get_otx_urls, [request.target]),
            ("live_hosts", check_live_hosts, [[request.target]]),
            ("parameters", find_parameters, [request.target]),
            ("directories", find_directories, [request.target]),
            ("technologies", detect_tech, [request.target])
        ]
        
        for name, func, args in modules:
            try:
                result = await asyncio.wait_for(func(*args), timeout=timeout)
                results[name] = result if result else []
                print(f"✅ {name}: {len(results[name])} items")
            except Exception as e:
                print(f"⚠️ {name} failed: {e}")
                results[name] = []
        
        scan_id = str(uuid.uuid4())
        scan_results[scan_id] = results
        
        return JSONResponse(content=results)
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== AI BUGREAPER ENDPOINT ====================

@app.post("/ai-scan")
async def ai_powered_scan(request: AIScanRequest):
    """Run BugReaper AI vulnerability scan"""
    print(f"🤖 BugReaper AI scan started for: {request.target}")
    
    if not AI_MODULES_LOADED:
        return JSONResponse(status_code=501, content={"error": "AI modules not loaded"})
    
    try:
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {"status": "scanning", "progress": 0}
        
        async with BugReaperEngine(request.target) as engine:
            active_scans[scan_id]["progress"] = 30
            findings = await engine.scan_all()
            
            findings_dict = []
            for f in findings:
                if hasattr(f, '__dict__'):
                    findings_dict.append(f.__dict__)
                else:
                    findings_dict.append(f)
            
            result = {
                "scan_id": scan_id,
                "target": request.target,
                "timestamp": datetime.now().isoformat(),
                "scan_type": "ai_bugreaper",
                "total_findings": len(findings_dict),
                "critical": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'critical'),
                "high": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'high'),
                "medium": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'medium'),
                "low": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'low'),
                "findings": findings_dict
            }
            
            scan_results[scan_id] = result
            active_scans[scan_id]["progress"] = 100
            del active_scans[scan_id]
            
            return JSONResponse(content=result)
            
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== OWASP API SCANNER ENDPOINT ====================

@app.post("/api-scan")
async def api_security_scan(request: APIScanRequest):
    """Run OWASP API Top 10 security scan"""
    print(f"🔌 API Security scan started for: {request.target}")
    
    if not AI_MODULES_LOADED:
        return JSONResponse(status_code=501, content={"error": "API scanner not loaded"})
    
    try:
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {"status": "scanning", "progress": 0}
        
        async with OWASPAPIScanner(request.target, request.api_base) as scanner:
            active_scans[scan_id]["progress"] = 20
            endpoints = await scanner.discover_endpoints()
            
            active_scans[scan_id]["progress"] = 40
            findings = await scanner.scan_all()
            
            findings_dict = []
            for f in findings:
                if hasattr(f, '__dict__'):
                    findings_dict.append(f.__dict__)
                else:
                    findings_dict.append(f)
            
            result = {
                "scan_id": scan_id,
                "target": request.target,
                "timestamp": datetime.now().isoformat(),
                "scan_type": "owasp_api_2026",
                "endpoints_discovered": endpoints,
                "total_findings": len(findings_dict),
                "findings": findings_dict
            }
            
            scan_results[scan_id] = result
            active_scans[scan_id]["progress"] = 100
            del active_scans[scan_id]
            
            return JSONResponse(content=result)
            
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== CI/CD SCANNER ENDPOINT ====================

@app.post("/cicd-scan")
async def cicd_security_scan(request: CICDScanRequest):
    """Scan CI/CD pipelines for security issues"""
    print(f"🔄 CI/CD scan started for: {request.repo_url}")
    
    if not AI_MODULES_LOADED:
        return JSONResponse(status_code=501, content={"error": "CI/CD scanner not loaded"})
    
    try:
        scan_id = str(uuid.uuid4())
        scanner = CICDScanner(request.repo_url, request.token)
        findings = scanner.scan_all()
        
        findings_dict = []
        for f in findings:
            if hasattr(f, '__dict__'):
                findings_dict.append(f.__dict__)
            else:
                findings_dict.append(f)
        
        result = {
            "scan_id": scan_id,
            "repository": request.repo_url,
            "branch": request.branch,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "cicd_security",
            "total_findings": len(findings_dict),
            "critical": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'critical'),
            "high": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'high'),
            "medium": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'medium'),
            "low": sum(1 for f in findings_dict if str(f.get('severity', '')).lower() == 'low'),
            "findings": findings_dict
        }
        
        scan_results[scan_id] = result
        return JSONResponse(content=result)
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== AI REPORT GENERATOR ENDPOINT ====================

@app.post("/generate-report/{scan_id}")
async def generate_security_report(scan_id: str, request: ReportRequest):
    """Generate AI-powered security report"""
    print(f"📄 Generating {request.format} report for scan: {scan_id}")
    
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not AI_MODULES_LOADED:
        return JSONResponse(status_code=501, content={"error": "Report generator not loaded"})
    
    try:
        scan_data = scan_results[scan_id]
        generator = AIReportGenerator(scan_data)
        
        if request.format == "pdf":
            filename = f"report_{scan_id}.pdf"
            generator.generate_pdf_report(filename)
        elif request.format == "html":
            filename = f"report_{scan_id}.html"
            generator.generate_html_report(filename)
        else:
            return JSONResponse(content=scan_data)
        
        return FileResponse(
            filename,
            media_type=f"application/{request.format}",
            filename=f"aionx_report_{scan_id}.{request.format}"
        )
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== BUG BOUNTY SUBMISSION ENDPOINT ====================

@app.post("/submit-to-bugbounty")
async def submit_to_bugbounty(request: BugBountySubmission):
    """Submit findings to bug bounty platforms"""
    print(f"🎯 Submitting to {request.platform}")
    
    if not AI_MODULES_LOADED:
        return JSONResponse(status_code=501, content={"error": "Bug bounty modules not loaded"})
    
    try:
        config = {
            "hackerone": {
                "username": os.getenv("HACKERONE_USERNAME", ""),
                "api_key": os.getenv("HACKERONE_API_KEY", "")
            },
            "bugcrowd": {
                "token": os.getenv("BUGGROWD_TOKEN", "")
            }
        }
        
        submitter = AutoSubmitter(config)
        result = await submitter.submit_finding(
            request.vulnerability,
            {"platform": request.platform, "program": request.program_id}
        )
        
        return JSONResponse(content={
            "status": "submitted",
            "platform": request.platform,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== COMPLETE SCAN ENDPOINT (ALL FEATURES) ====================

@app.post("/complete-scan")
async def complete_security_assessment(request: ReconRequest):
    """Run complete security assessment with all modules"""
    print(f"🚀 COMPLETE SECURITY ASSESSMENT started for: {request.target}")
    
    try:
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {"status": "running", "progress": 0}
        
        results = {
            "scan_id": scan_id,
            "target": request.target,
            "timestamp": datetime.now().isoformat(),
            "phases": {}
        }
        
        # Phase 1: Reconnaissance
        print("\n📡 Phase 1: Reconnaissance...")
        active_scans[scan_id]["progress"] = 10
        active_scans[scan_id]["status"] = "Running reconnaissance..."
        
        recon_results = await run_recon(request)
        if isinstance(recon_results, JSONResponse):
            recon_results = json.loads(recon_results.body)
        results["phases"]["reconnaissance"] = recon_results
        
        # Phase 2: AI BugReaper Analysis
        if AI_MODULES_LOADED:
            print("\n🧠 Phase 2: AI BugReaper Analysis...")
            active_scans[scan_id]["progress"] = 30
            active_scans[scan_id]["status"] = "Running AI vulnerability analysis..."
            
            async with BugReaperEngine(request.target) as engine:
                ai_findings = await engine.scan_all()
                ai_findings_dict = [f.__dict__ for f in ai_findings]
                results["phases"]["ai_analysis"] = {
                    "total_findings": len(ai_findings_dict),
                    "findings": ai_findings_dict
                }
        
        # Phase 3: API Security Scan
        if AI_MODULES_LOADED:
            print("\n🔌 Phase 3: API Security Scan...")
            active_scans[scan_id]["progress"] = 50
            active_scans[scan_id]["status"] = "Scanning APIs..."
            
            async with OWASPAPIScanner(request.target) as scanner:
                endpoints = await scanner.discover_endpoints()
                api_findings = await scanner.scan_all()
                api_findings_dict = [f.__dict__ for f in api_findings]
                results["phases"]["api_security"] = {
                    "endpoints": endpoints,
                    "total_findings": len(api_findings_dict),
                    "findings": api_findings_dict
                }
        
        # Phase 4: Generate Report
        print("\n📊 Phase 4: Generating Report...")
        active_scans[scan_id]["progress"] = 80
        active_scans[scan_id]["status"] = "Generating report..."
        
        if AI_MODULES_LOADED:
            generator = AIReportGenerator(results)
            report_html = generator.generate_html_report(f"complete_scan_{scan_id}.html")
            results["phases"]["report"] = {
                "path": report_html,
                "format": "html"
            }
        
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["status"] = "completed"
        
        results["summary"] = {
            "total_phases": len(results["phases"]),
            "completion_time": datetime.now().isoformat(),
            "scan_id": scan_id
        }
        
        scan_results[scan_id] = results
        del active_scans[scan_id]
        
        print(f"\n✅ Complete assessment finished for {request.target}")
        return JSONResponse(content=results)
        
    except Exception as e:
        if scan_id in active_scans:
            del active_scans[scan_id]
        return JSONResponse(status_code=500, content={"error": str(e)})

# ==================== SCAN MANAGEMENT ENDPOINTS ====================

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
            vulnerabilities=scan_results[scan_id].get("findings", [])
        )
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/scans")
async def list_scans():
    """List all scans"""
    return {
        "active": list(active_scans.keys()),
        "completed": list(scan_results.keys()),
        "total_active": len(active_scans),
        "total_completed": len(scan_results)
    }

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan result"""
    if scan_id in scan_results:
        del scan_results[scan_id]
        return {"status": "deleted"}
    elif scan_id in active_scans:
        del active_scans[scan_id]
        return {"status": "cancelled"}
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

# ==================== EXPORT ENDPOINTS ====================

@app.get("/export/{scan_id}")
async def export_scan(scan_id: str, format: str = "json"):
    """Export scan results in various formats"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    if format == "json":
        filename = f"scan_{scan_id}.json"
        filepath = f"/tmp/{filename}"
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)
        return FileResponse(filepath, filename=filename)
    
    elif format == "txt":
        filename = f"scan_{scan_id}.txt"
        filepath = f"/tmp/{filename}"
        with open(filepath, 'w') as f:
            f.write(f"AION-X Scan Report\n")
            f.write(f"Target: {scan_data.get('target')}\n")
            f.write(f"Time: {scan_data.get('timestamp')}\n")
            f.write("-" * 50 + "\n")
            for phase, data in scan_data.get('phases', {}).items():
                f.write(f"\n{phase.upper()}:\n")
                f.write(json.dumps(data, indent=2)[:500] + "...\n")
        return FileResponse(filepath, filename=filename)
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

# ==================== HEALTH CHECK ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "reconnaissance": RECON_MODULES_LOADED,
            "ai_bugreaper": AI_MODULES_LOADED,
            "api_scanner": AI_MODULES_LOADED,
            "cicd_scanner": AI_MODULES_LOADED,
            "reporting": AI_MODULES_LOADED,
            "bugbounty": AI_MODULES_LOADED
        },
        "active_scans": len(active_scans),
        "completed_scans": len(scan_results)
    }

@app.get("/features")
async def list_features():
    """List all available features"""
    return {
        "reconnaissance": {
            "subdomain_scanner": RECON_MODULES_LOADED,
            "wayback_urls": RECON_MODULES_LOADED,
            "otx_urls": RECON_MODULES_LOADED,
            "live_hosts": RECON_MODULES_LOADED,
            "param_discovery": RECON_MODULES_LOADED,
            "dir_finder": RECON_MODULES_LOADED,
            "tech_detector": RECON_MODULES_LOADED
        },
        "ai_powered": {
            "bugreaper_framework": AI_MODULES_LOADED,
            "owasp_api_scanner": AI_MODULES_LOADED,
            "cicd_scanner": AI_MODULES_LOADED,
            "ai_report_generator": AI_MODULES_LOADED,
            "bugbounty_integration": AI_MODULES_LOADED
        }
    }

# ==================== MAIN ====================

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🚀 AION-X 3.0 - Complete AI Security Platform")
    print("="*60)
    print(f"📁 Project root: {project_root}")
    print(f"✅ Recon modules: {RECON_MODULES_LOADED}")
    print(f"✅ AI modules: {AI_MODULES_LOADED}")
    print(f"🌐 API Documentation: http://localhost:8000/docs")
    print(f"🎯 Frontend: http://localhost:3000")
    print("="*60 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
