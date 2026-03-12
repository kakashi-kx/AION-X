"""
AI-Powered Security Report Generator
Creates professional reports with ChatGPT-style analysis
"""

import json
import datetime
from typing import List, Dict, Any
from jinja2 import Template
import markdown
import pdfkit  # Install: pip install pdfkit

class AIReportGenerator:
    def __init__(self, scan_results: Dict[str, Any]):
        self.results = scan_results
        self.target = scan_results.get('target', 'Unknown')
        self.timestamp = datetime.datetime.now()
        
    def generate_summary(self) -> str:
        """Generate AI-powered executive summary"""
        findings_count = len(self.results.get('vulnerabilities', []))
        subdomains_count = len(self.results.get('subdomains', []))
        urls_count = len(self.results.get('urls', []))
        
        summary = f"""
# AI-Powered Security Assessment Report

## Executive Summary

This report presents the findings of an automated security assessment conducted on **{self.target}** 
on **{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}**.

### Key Metrics
- **Total Subdomains Discovered**: {subdomains_count}
- **Total URLs Analyzed**: {urls_count}
- **Vulnerabilities Found**: {findings_count}

### Risk Overview
Based on the AI-powered analysis, the target's security posture indicates...
"""
        return summary
    
    def generate_vulnerability_analysis(self, vulns: List[Dict]) -> str:
        """Generate detailed vulnerability analysis"""
        if not vulns:
            return "## No Critical Vulnerabilities Found\n\nNo security issues were detected during this scan."
        
        analysis = "## Detailed Vulnerability Analysis\n\n"
        
        # Group by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x.get('severity', 'Low'), 4))
        
        for vuln in sorted_vulns:
            analysis += f"""
### {vuln.get('name')} - **{vuln.get('severity')} Severity** (CVSS: {vuln.get('cvss_score', 'N/A')})

**Description**  
{vuln.get('description', 'No description provided')}

**Technical Impact**  
{vuln.get('impact', 'See description for details')}

**Proof of Concept**  
{vuln.get('proof_of_concept', 'No PoC provided')}


**Remediation**  
{vuln.get('remediation', 'No remediation steps provided')}

**Affected Endpoint**  
`{vuln.get('affected_url', 'N/A')}`

---
"""
        return analysis
    
    def generate_remediation_plan(self, vulns: List[Dict]) -> str:
        """Generate prioritized remediation plan"""
        if not vulns:
            return ""
        
        plan = "## Prioritized Remediation Plan\n\n"
        plan += "| Priority | Vulnerability | Effort | Impact | Recommended Action |\n"
        plan += "|----------|---------------|--------|--------|-------------------|\n"
        
        for vuln in vulns:
            severity = vuln.get('severity', 'Low')
            priority = {
                'Critical': '🔴 Immediate',
                'High': '🟠 High',
                'Medium': '🟡 Medium',
                'Low': '🟢 Low'
            }.get(severity, '⚪ Info')
            
            effort = {
                'Critical': 'High',
                'High': 'Medium',
                'Medium': 'Low',
                'Low': 'Very Low'
            }.get(severity, 'Unknown')
            
            plan += f"| **{priority}** | {vuln.get('name')} | {effort} | **{severity}** | {vuln.get('remediation', 'See details')} |\n"
        
        return plan
    
    def generate_html_report(self, output_file: str = "report.html"):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AION-X Security Report - {{ target }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: white;
            margin: 0;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        .metric-value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .vulnerability {
            border-left: 4px solid;
            margin: 20px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .critical { border-color: #dc3545; }
        .high { border-color: #fd7e14; }
        .medium { border-color: #ffc107; }
        .low { border-color: #28a745; }
        .severity-badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 3px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 12px;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; color: #333; }
        .severity-low { background: #28a745; }
        pre {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #667eea;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AION-X Security Assessment Report</h1>
            <p>Target: {{ target }}</p>
            <p>Scan Date: {{ timestamp }}</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div>Subdomains</div>
                <div class="metric-value">{{ subdomains_count }}</div>
            </div>
            <div class="metric-card">
                <div>URLs</div>
                <div class="metric-value">{{ urls_count }}</div>
            </div>
            <div class="metric-card">
                <div>Parameters</div>
                <div class="metric-value">{{ params_count }}</div>
            </div>
            <div class="metric-card">
                <div>Vulnerabilities</div>
                <div class="metric-value">{{ vulns_count }}</div>
            </div>
        </div>
        
        {{ summary }}
        
        {{ vulnerability_analysis }}
        
        {{ remediation_plan }}
        
        <div class="footer">
            <p>Generated by AION-X AI Security Platform | {{ timestamp }}</p>
            <p>© 2026 AION-X - AI-Powered Penetration Testing</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Prepare data
        vulns = self.results.get('vulnerabilities', [])
        
        template = Template(html_template)
        html_content = template.render(
            target=self.target,
            timestamp=self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            subdomains_count=len(self.results.get('subdomains', [])),
            urls_count=len(self.results.get('urls', [])),
            params_count=len(self.results.get('parameters', [])),
            vulns_count=len(vulns),
            summary=self.generate_summary(),
            vulnerability_analysis=self.generate_vulnerability_analysis(vulns),
            remediation_plan=self.generate_remediation_plan(vulns)
        )
        
        # Save HTML
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"✅ HTML report generated: {output_file}")
        return output_file
    
    def generate_pdf_report(self, output_file: str = "report.pdf"):
        """Generate PDF report"""
        html_file = self.generate_html_report("temp_report.html")
        
        try:
            # Convert HTML to PDF
            pdfkit.from_file(html_file, output_file, options={
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': 'UTF-8'
            })
            print(f"✅ PDF report generated: {output_file}")
            
            # Clean up temp file
            import os
            os.remove(html_file)
            
        except Exception as e:
            print(f"❌ PDF generation failed: {e}")
            print("Install wkhtmltopdf: sudo apt-get install wkhtmltopdf")

# API endpoint for report generation
async def generate_report_endpoint(scan_id: str, format: str = "html"):
    """FastAPI endpoint for report generation"""
    from fastapi.responses import FileResponse
    
    # Get scan results from database
    scan_results = get_scan_results(scan_id)  # Implement this
    
    generator = AIReportGenerator(scan_results)
    
    if format == "pdf":
        filename = f"report_{scan_id}.pdf"
        generator.generate_pdf_report(filename)
    else:
        filename = f"report_{scan_id}.html"
        generator.generate_html_report(filename)
    
    return FileResponse(
        filename,
        media_type=f"application/{format}",
        filename=f"aionx_report_{scan_id}.{format}"
    )
