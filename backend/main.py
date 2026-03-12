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
import base64

# ==================== MODULE IMPORTS ====================

# Reconnaissance Modules
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

# AI-Powered Modules (2026 Features)
try:
    from modules.ai.bugreaper import BugReaperEngine, VulnerabilityClass
    from modules.api.owasp_api_scanner import OWASPAPIScanner, APIVulnerability
    from modules.devsecops.cicd_scanner import CICDScanner, CICDVulnerability
    from modules.reporting.ai_report_generator import AIReportGenerator
    from modules.integrations.bugbounty_platforms import AutoSubmitter
    AI_MODULES_LOADED = True
    print("✅ AI modules loaded successfully (2026 features)")
except ImportError as e:
    print(f"⚠️ Warning: AI modules could not be imported: {e}")
    AI_MODULES_LOADED = False

# ==================== FASTAPI SETUP ====================

app = FastAPI(
    title="AION-X AI Penetration Testing Platform",
    version="2.0.0",
    description="AI-Powered Security Testing with 2026 Cutting-Edge Features"
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
    scan_depth: str = "standard"  # quick, standard, deep
    include_exploits: bool = False

class APIScanRequest(BaseModel):
    target: str
    api_base: str = "/api"
    scan_all_endpoints: bool = True

class CICDScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    token: Optional[str] = None

class ReportRequest(BaseModel):
    scan_id: str
    format: str = "html"  # html, pdf, json
    include_ai_analysis: bool = True

class BugBountySubmission(BaseModel):
    vulnerability: Dict[str, Any]
    platform: str  # hackerone, bugcrowd, intigriti
    program_id: str
    auto_submit: bool = False

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: float
    completed: bool
    vulnerabilities: Optional[List[Dict]] = None
    ai_insights: Optional[Dict] = None

# ==================== IN-MEMORY STORAGE ====================

active_scans = {}
scan_results = {}
bugreaper_config = {
    "hackerone": {
        "username": os.getenv("HACKERONE_USERNAME", ""),
        "api_key": os.getenv("HACKERONE_API_KEY", "")
    },
    "bugcrowd": {
        "token": os.getenv("BUGGROWD_TOKEN", "")
    },
    "intigriti": {
        "client_id": os.getenv("INTIGRITI_CLIENT_ID", ""),
        "client_secret": os.getenv("INTIGRITI_CLIENT_SECRET", "")
    }
}

# ==================== ROOT ENDPOINT ====================

@app.get("/")
async def root():
    return {
        "message": "AION-X AI Penetration Testing Platform",
        "version": "2.0.0",
        "features": {
            "recon_modules": RECON_MODULES_LOADED,
            "ai_modules_2026": AI_MODULES_LOADED,
            "bugreaper_framework": AI_MODULES_LOADED,
            "owasp_api_scanner": AI_MODULES_LOADED,
            "cicd_scanner": AI_MODULES_LOADED,
            "ai_report_generator": AI_MODULES_LOADED,
            "bugbounty_integration": AI_MODULES_LOADED
        },
        "status": "ready",
        "documentation": "/docs"
    }

# ==================== STATS ENDPOINT ====================

@app.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    return {
        "total_scans": len(scan_results),
        "active_scans": len(active_scans),
        "total_vulnerabilities": sum(len(r.get("vulnerabilities", [])) for r in scan_results.values()),
        "total_hosts": len(scan_results),
        "critical_vulns": sum(1 for r in scan_results.values() for v in r.get("vulnerabilities", []) if v.get("severity") == "Critical"),
        "high_vulns": sum(1 for r in scan_results.values() for v in r.get("vulnerabilities", []) if v.get("severity") == "High"),
        "medium_vulns": sum(1 for r in scan_results.values() for v in r.get("vulnerabilities", []) if v.get("severity") == "Medium"),
        "low_vulns": sum(1 for r in scan_results.values() for v in r.get("vulnerabilities", []) if v.get("severity") == "Low"),
        "scan_dates": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "scan_counts": [0, 0, 0, 0, 0, 0, 0]
    }

# ==================== RECONNAISSANCE ENDPOINT ====================

@app.post("/recon")
async def run_recon(request: ReconRequest):
    """Run reconnaissance on target with timeouts"""
    print(f"=== Recon request received for target: {request.target} ===")
    
    try:
        # Set timeout for each module (30 seconds)
        timeout_seconds = 30
        
        # Initialize results
        results = {
            "target": request.target,
            "timestamp": datetime.now().isoformat(),
            "subdomains": [],
            "urls": [],
            "otx_urls": [],
            "live_hosts": [],
            "parameters": [],
            "directories": [],
            "technologies": [],
            "ai_insights": {}
        }
        
        # Run modules with individual timeouts
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
                print(f"Running {name}...")
                result = await asyncio.wait_for(func(*args), timeout=timeout_seconds)
                results[name] = result if result is not None else []
                print(f"✅ {name} completed: {len(results[name]) if isinstance(results[name], list) else 0} items")
            except asyncio.TimeoutError:
                print(f"⚠️ {name} timed out after {timeout_seconds} seconds")
                results[name] = []
            except Exception as e:
                print(f"⚠️ {name} failed: {e}")
                results[name] = []
        
        # Add AI insights if available
        if AI_MODULES_LOADED:
            results["ai_insights"] = {
                "total_findings": sum(len(v) for v in results.values() if isinstance(v, list)),
                "risk_score": calculate_risk_score(results),
                "recommendations": generate_recommendations(results)
            }
        
        # Store results
        scan_id = str(uuid.uuid4())
        scan_results[scan_id] = results
        
        print(f"=== Recon completed for {request.target} ===")
        print(f"   Subdomains: {len(results['subdomains'])}")
        print(f"   URLs: {len(results['urls'])}")
        print(f"   OTX URLs: {len(results['otx_urls'])}")
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

# ==================== 2026 AI-POWERED FEATURES ====================

@app.post("/ai-scan")
async def ai_powered_scan(request: AIScanRequest):
    """Run AI-powered vulnerability scan with BugReaper framework"""
    print(f"🤖 AI-Powered BugReaper scan started for: {request.target}")
    
    try:
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {
            "status": "scanning",
            "progress": 0,
            "target": request.target,
            "type": "ai_bugreaper"
        }
        
        # Run BugReaper scan
        async with BugReaperEngine(request.target) as engine:
            # Update progress
            active_scans[scan_id]["progress"] = 30
            active_scans[scan_id]["status"] = "Running 18 vulnerability checks..."
            
            findings = await engine.scan_all()
            
            active_scans[scan_id]["progress"] = 80
            active_scans[scan_id]["status"] = "Analyzing results with AI..."
            
            # Convert findings to dict
            findings_dict = [f.__dict__ for f in findings]
            
            # Store results
            scan_results[scan_id] = {
                "target": request.target,
                "timestamp": datetime.now().isoformat(),
                "scan_type": "ai_bugreaper",
                "vulnerabilities": findings_dict,
                "summary": {
                    "total": len(findings_dict),
                    "critical": sum(1 for f in findings_dict if f.get("severity") == "Critical"),
                    "high": sum(1 for f in findings_dict if f.get("severity") == "High"),
                    "medium": sum(1 for f in findings_dict if f.get("severity") == "Medium"),
                    "low": sum(1 for f in findings_dict if f.get("severity") == "Low"),
                    "confidence_avg": sum(f.get("confidence", 0) for f in findings_dict) / len(findings_dict) if findings_dict else 0
                }
            }
            
            active_scans[scan_id]["progress"] = 100
            active_scans[scan_id]["status"] = "completed"
            del active_scans[scan_id]
            
            return JSONResponse(content=scan_results[scan_id])
            
    except Exception as e:
        print(f"❌ AI scan failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "AI-powered scan failed"}
        )

@app.post("/api-scan")
async def api_security_scan(request: APIScanRequest):
    """Run OWASP API Security Top 10 scan"""
    print(f"🔌 OWASP API Security scan started for: {request.target}")
    
    try:
        scan_id = str(uuid.uuid4())
        active_scans[scan_id] = {
            "status": "scanning",
            "progress": 0,
            "target": request.target,
            "type": "owasp_api"
        }
        
        async with OWASPAPIScanner(request.target, request.api_base) as scanner:
            # Discover endpoints
            active_scans[scan_id]["progress"] = 20
            active_scans[scan_id]["status"] = "Discovering API endpoints..."
            
            endpoints = await scanner.discover_endpoints()
            
            active_scans[scan_id]["progress"] = 40
            active_scans[scan_id]["status"] = f"Found {len(endpoints)} endpoints, running security checks..."
            
            # Run all API checks
            findings = await scanner.scan_all()
            
            active_scans[scan_id]["progress"] = 90
            active_scans[scan_id]["status"] = "Finalizing results..."
            
            # Convert findings to dict
            findings_dict = [f.__dict__ for f in findings]
            
            # Store results
            scan_results[scan_id] = {
                "target": request.target,
                "timestamp": datetime.now().isoformat(),
                "scan_type": "owasp_api_2026",
                "endpoints_discovered": endpoints,
                "vulnerabilities": findings_dict,
                "summary": {
                    "total": len(findings_dict),
                    "api1_bola": sum(1 for f in findings_dict if "API1" in f.get("category", "")),
                    "api2_auth": sum(1 for f in findings_dict if "API2" in f.get("category", "")),
                    "api3_bopla": sum(1 for f in findings_dict if "API3" in f.get("category", "")),
                    "api6_business": sum(1 for f in findings_dict if "API6" in f.get("category", ""))
                }
            }
            
            active_scans[scan_id]["progress"] = 100
            active_scans[scan_id]["status"] = "completed"
            del active_scans[scan_id]
            
            return JSONResponse(content=scan_results[scan_id])
            
    except Exception as e:
        print(f"❌ API scan failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "API security scan failed"}
        )

@app.post("/cicd-scan")
async def cicd_security_scan(request: CICDScanRequest):
    """Scan CI/CD pipelines for security issues"""
    print(f"🔄 CI/CD Security scan started for: {request.repo_url}")
    
    try:
        scan_id = str(uuid.uuid4())
        
        scanner = CICDScanner(request.repo_url, request.token)
        findings = scanner.scan_all()
        
        findings_dict = [f.__dict__ for f in findings]
        
        scan_results[scan_id] = {
            "repository": request.repo_url,
            "branch": request.branch,
            "timestamp": datetime.now().isoformat(),
            "scan_type": "cicd_security",
            "vulnerabilities": findings_dict,
            "summary": {
                "total": len(findings_dict),
                "critical": sum(1 for f in findings_dict if f.get("severity") == "Critical"),
                "high": sum(1 for f in findings_dict if f.get("severity") == "High"),
                "medium": sum(1 for f in findings_dict if f.get("severity") == "Medium"),
                "low": sum(1 for f in findings_dict if f.get("severity") == "Low")
            }
        }
        
        return JSONResponse(content=scan_results[scan_id])
        
    except Exception as e:
        print(f"❌ CI/CD scan failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "CI/CD security scan failed"}
        )

@app.post("/generate-report/{scan_id}")
async def generate_security_report(scan_id: str, request: ReportRequest):
    """Generate AI-powered security report"""
    print(f"📄 Generating {request.format} report for scan: {scan_id}")
    
    try:
        if scan_id not in scan_results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        scan_data = scan_results[scan_id]
        
        # Add AI insights if requested
        if request.include_ai_analysis and AI_MODULES_LOADED:
            generator = AIReportGenerator(scan_data)
            
            if request.format == "pdf":
                filename = f"report_{scan_id}.pdf"
                generator.generate_pdf_report(filename)
            elif request.format == "html":
                filename = f"report_{scan_id}.html"
                generator.generate_html_report(filename)
            else:  # json
                return JSONResponse(content=scan_data)
            
            return FileResponse(
                filename,
                media_type=f"application/{request.format}",
                filename=f"aionx_report_{scan_id}.{request.format}"
            )
        else:
            # Return raw JSON if no AI report requested
            return JSONResponse(content=scan_data)
            
    except Exception as e:
        print(f"❌ Report generation failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "Report generation failed"}
        )

@app.post("/submit-to-bugbounty")
async def submit_vulnerability(request: BugBountySubmission):
    """Submit vulnerability to bug bounty platform"""
    print(f"🎯 Submitting finding to {request.platform}")
    
    try:
        if not AI_MODULES_LOADED:
            return JSONResponse(
                status_code=501,
                content={"error": "Bug bounty integration modules not loaded"}
            )
        
        submitter = AutoSubmitter(bugreaper_config)
        
        result = await submitter.submit_finding(
            request.vulnerability,
            {
                "platform": request.platform,
                "program": request.program_id
            }
        )
        
        return JSONResponse(content={
            "status": "submitted",
            "platform": request.platform,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"❌ Bug bounty submission failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "Submission failed"}
        )

@app.post("/analyze-code")
async def analyze_code(file: UploadFile = File(...)):
    """Analyze uploaded code for vulnerabilities"""
    print(f"📝 Analyzing code file: {file.filename}")
    
    try:
        content = await file.read()
        
        # Simple analysis based on file extension
        findings = []
        
        if file.filename.endswith('.py'):
            # Python analysis
            lines = content.decode().split('\n')
            for i, line in enumerate(lines):
                if 'eval(' in line:
                    findings.append({
                        "line": i + 1,
                        "code": line.strip(),
                        "issue": "Use of eval() is dangerous",
                        "severity": "High",
                        "remediation": "Avoid eval() for dynamic code execution"
                    })
                if 'pickle.load' in line:
                    findings.append({
                        "line": i + 1,
                        "code": line.strip(),
                        "issue": "Unsafe deserialization with pickle",
                        "severity": "Critical",
                        "remediation": "Use safe serialization formats like JSON"
                    })
                    
        elif file.filename.endswith('.js'):
            # JavaScript analysis
            lines = content.decode().split('\n')
            for i, line in enumerate(lines):
                if 'eval(' in line:
                    findings.append({
                        "line": i + 1,
                        "code": line.strip(),
                        "issue": "Use of eval() is dangerous",
                        "severity": "High",
                        "remediation": "Avoid eval() for dynamic code execution"
                    })
                if 'innerHTML' in line and '=' in line:
                    findings.append({
                        "line": i + 1,
                        "code": line.strip(),
                        "issue": "Potential XSS via innerHTML",
                        "severity": "High",
                        "remediation": "Use textContent instead of innerHTML"
                    })
        
        return JSONResponse(content={
            "filename": file.filename,
            "size": len(content),
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "Critical"),
                "high": sum(1 for f in findings if f.get("severity") == "High"),
                "medium": sum(1 for f in findings if f.get("severity") == "Medium"),
                "low": sum(1 for f in findings if f.get("severity") == "Low")
            }
        })
        
    except Exception as e:
        print(f"❌ Code analysis failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "detail": "Code analysis failed"}
        )

# ==================== VULNERABILITY SCANNING ====================

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
            vulnerabilities=scan_results[scan_id].get("vulnerabilities", []),
            ai_insights=scan_results[scan_id].get("ai_insights", {})
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
        return {"status": "deleted", "scan_id": scan_id}
    elif scan_id in active_scans:
        del active_scans[scan_id]
        return {"status": "cancelled", "scan_id": scan_id}
    else:
        raise HTTPException(status_code=404, detail="Scan not found")

# ==================== EXPORT FUNCTIONS ====================

@app.get("/export/{scan_type}")
async def export_results(scan_type: str):
    """Export scan results"""
    data = {
        "type": scan_type,
        "results": [],
        "exported_at": datetime.now().isoformat()
    }
    
    # Collect all results of that type
    for scan_id, scan_data in scan_results.items():
        if scan_type in scan_data:
            data["results"].extend(scan_data[scan_type])
    
    filename = f"export_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = f"/tmp/{filename}"
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    return FileResponse(filepath, filename=filename, media_type="application/json")

@app.get("/export-scan/{scan_id}")
async def export_scan(scan_id: str, format: str = "json"):
    """Export specific scan in various formats"""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = scan_results[scan_id]
    
    if format == "json":
        filename = f"scan_{scan_id}.json"
        filepath = f"/tmp/{filename}"
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2)
        return FileResponse(filepath, filename=filename, media_type="application/json")
    
    elif format == "html":
        # Generate HTML report
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>AION-X Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                .vuln {{ border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; background: #f8f9fa; }}
                .critical {{ border-color: #dc3545; }}
                .high {{ border-color: #fd7e14; }}
                .medium {{ border-color: #ffc107; }}
                .low {{ border-color: #28a745; }}
            </style>
        </head>
        <body>
            <h1>AION-X Security Scan Report</h1>
            <p>Target: {target}</p>
            <p>Time: {time}</p>
            <h2>Findings</h2>
            {findings}
        </body>
        </html>
        """
        
        findings_html = ""
        for vuln in scan_data.get("vulnerabilities", []):
            severity = vuln.get("severity", "Low").lower()
            findings_html += f"""
            <div class="vuln {severity}">
                <h3>{vuln.get('name', 'Unknown')}</h3>
                <p><strong>Severity:</strong> {vuln.get('severity', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'N/A')}</p>
                <p><strong>Affected URL:</strong> {vuln.get('affected_url', 'N/A')}</p>
                <p><strong>Remediation:</strong> {vuln.get('remediation', 'N/A')}</p>
            </div>
            """
        
        html_content = html_template.format(
            target=scan_data.get("target", "Unknown"),
            time=scan_data.get("timestamp", datetime.now().isoformat()),
            findings=findings_html or "<p>No vulnerabilities found</p>"
        )
        
        filename = f"scan_{scan_id}.html"
        filepath = f"/tmp/{filename}"
        with open(filepath, 'w') as f:
            f.write(html_content)
        return FileResponse(filepath, filename=filename, media_type="text/html")
    
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

# ==================== BACKGROUND TASKS ====================

async def run_vulnerability_scan(scan_id: str, request: ScanRequest):
    """Run vulnerability scan in background"""
    try:
        active_scans[scan_id]["status"] = "scanning"
        
        for i in range(1, 11):
            await asyncio.sleep(2)
            active_scans[scan_id]["progress"] = i * 10
            active_scans[scan_id]["status"] = f"Scanning... {i*10}%"
        
        # Simulate vulnerabilities
        vulnerabilities = [
            {
                "name": "SQL Injection",
                "severity": "Critical",
                "description": "SQL injection vulnerability in login parameter",
                "cve_id": "CVE-2023-1234",
                "cvss_score": 9.8,
                "affected_url": f"{request.target}/login",
                "remediation": "Use parameterized queries",
                "proof_of_concept": "' OR '1'='1",
                "confidence": 0.95
            },
            {
                "name": "XSS Vulnerability",
                "severity": "Medium",
                "description": "Reflected XSS in search parameter",
                "cve_id": "CVE-2023-5678",
                "cvss_score": 6.1,
                "affected_url": f"{request.target}/search",
                "remediation": "Implement output encoding",
                "proof_of_concept": "<script>alert(1)</script>",
                "confidence": 0.88
            },
            {
                "name": "IDOR",
                "severity": "High",
                "description": "Insecure Direct Object Reference in user profile",
                "cve_id": "CVE-2023-9012",
                "cvss_score": 7.5,
                "affected_url": f"{request.target}/api/user/1337",
                "remediation": "Implement proper access controls",
                "proof_of_concept": "Changing user ID returns other users' data",
                "confidence": 0.92
            }
        ]
        
        # Add AI insights
        ai_insights = {
            "total_findings": len(vulnerabilities),
            "risk_score": 7.2,
            "recommendations": [
                "Implement WAF to block SQL injection attempts",
                "Add Content-Security-Policy headers",
                "Conduct security training for developers"
            ],
            "attack_vector_analysis": "Multiple injection points identified",
            "priority_order": ["SQL Injection", "IDOR", "XSS"]
        }
        
        scan_results[scan_id] = {
            "target": request.target,
            "scan_type": request.scan_type,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities,
            "ai_insights": ai_insights
        }
        
        del active_scans[scan_id]
        
    except Exception as e:
        active_scans[scan_id]["status"] = f"failed: {str(e)}"
        active_scans[scan_id]["progress"] = 0

# ==================== HELPER FUNCTIONS ====================

def calculate_risk_score(results: Dict) -> float:
    """Calculate overall risk score based on findings"""
    score = 0
    weights = {
        "subdomains": 0.1,
        "urls": 0.2,
        "parameters": 0.3,
        "technologies": 0.1
    }
    
    for key, weight in weights.items():
        if key in results and isinstance(results[key], list):
            score += min(len(results[key]) * weight, 1.0)
    
    return min(round(score, 2), 1.0)

def generate_recommendations(results: Dict) -> List[str]:
    """Generate AI-powered recommendations"""
    recommendations = []
    
    if len(results.get("subdomains", [])) > 10:
        recommendations.append("Large attack surface detected - prioritize subdomain consolidation")
    
    if len(results.get("parameters", [])) > 20:
        recommendations.append("Many parameters exposed - implement strict input validation")
    
    if "nginx" in str(results.get("technologies", [])):
        recommendations.append("Nginx detected - ensure proper security headers configuration")
    
    if not recommendations:
        recommendations.append("Continue monitoring and regular security assessments")
    
    return recommendations

# ==================== HEALTH CHECK ====================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "modules": {
            "recon": RECON_MODULES_LOADED,
            "ai_2026": AI_MODULES_LOADED
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
        "ai_powered_2026": {
            "bugreaper_framework": AI_MODULES_LOADED,
            "owasp_api_scanner": AI_MODULES_LOADED,
            "cicd_scanner": AI_MODULES_LOADED,
            "ai_report_generator": AI_MODULES_LOADED,
            "bugbounty_integration": AI_MODULES_LOADED,
            "code_analyzer": AI_MODULES_LOADED
        }
    }

# ==================== MAIN ====================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting AION-X 2.0 with 2026 AI Features...")
    print(f"📁 Project root: {project_root}")
    print(f"✅ Recon modules: {RECON_MODULES_LOADED}")
    print(f"✅ AI modules: {AI_MODULES_LOADED}")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
