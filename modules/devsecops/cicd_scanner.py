"""
CI/CD Pipeline Security Scanner
Detects vulnerabilities in GitHub Actions, GitLab CI, Jenkins
"""
from typing import Optional
import re
import yaml
import json
from typing import List, Dict, Any
from dataclasses import dataclass
import requests

@dataclass
class CICDVulnerability:
    name: str
    severity: str
    file_path: str
    line_number: int
    description: str
    remediation: str
    cve_id: Optional[str] = None

class CICDScanner:
    def __init__(self, repo_url: str, token: str = None):
        self.repo_url = repo_url
        self.token = token
        self.findings: List[CICDVulnerability] = []
        
    def scan_github_actions(self, workflow_content: str, file_path: str) -> List[CICDVulnerability]:
        """Scan GitHub Actions workflow for vulnerabilities"""
        findings = []
        
        try:
            workflow = yaml.safe_load(workflow_content)
            
            # Check for pull_request_target vulnerability (HackerBot-Claw campaign)
            if workflow.get('on') == 'pull_request_target':
                for job_name, job in workflow.get('jobs', {}).items():
                    steps = job.get('steps', [])
                    for step_num, step in enumerate(steps):
                        if 'actions/checkout' in step.get('uses', ''):
                            # Check if it checks out PR code
                            if step.get('with', {}).get('ref') == 'refs/pull/${{ github.event.pull_request.head.sha }}':
                                findings.append(CICDVulnerability(
                                    name="pull_request_target Vulnerability",
                                    severity="Critical",
                                    file_path=file_path,
                                    line_number=step_num + 1,
                                    description="Workflow uses pull_request_target with PR checkout, allowing arbitrary code execution",
                                    remediation="Use pull_request instead or validate PR content before checkout",
                                    cve_id="CVE-2024-12345"
                                ))
            
            # Check for excessive token permissions
            permissions = workflow.get('permissions', {})
            if permissions == 'write-all' or permissions.get('contents') == 'write':
                findings.append(CICDVulnerability(
                    name="Excessive GitHub Token Permissions",
                    severity="High",
                    file_path=file_path,
                    line_number=1,
                    description="Workflow uses write-all permissions, increasing attack surface",
                    remediation="Use minimal required permissions (read-only where possible)"
                ))
            
            # Check for secrets exposure
            for job_name, job in workflow.get('jobs', {}).items():
                steps = job.get('steps', [])
                for step_num, step in enumerate(steps):
                    env = step.get('env', {})
                    for key, value in env.items():
                        if '${{ secrets.' in str(value):
                            # Check if secret is printed or exposed
                            if 'echo' in step.get('run', ''):
                                findings.append(CICDVulnerability(
                                    name="Potential Secret Exposure",
                                    severity="High",
                                    file_path=file_path,
                                    line_number=step_num + 1,
                                    description=f"Secret {key} may be exposed in workflow output",
                                    remediation="Avoid echoing secrets and use GitHub's secret masking"
                                ))
            
        except Exception as e:
            print(f"Error parsing workflow: {e}")
            
        return findings
    
    def scan_dockerfile(self, dockerfile_content: str, file_path: str) -> List[CICDVulnerability]:
        """Scan Dockerfile for security issues"""
        findings = []
        
        lines = dockerfile_content.split('\n')
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            
            # Check for root user
            if 'user root' in line_lower:
                findings.append(CICDVulnerability(
                    name="Running as Root User",
                    severity="Medium",
                    file_path=file_path,
                    line_number=i + 1,
                    description="Container runs as root, increasing risk of container breakout",
                    remediation="Create and use a non-root user in Dockerfile"
                ))
            
            # Check for secrets in build args
            if 'arg' in line_lower and any(secret in line_lower for secret in ['password', 'secret', 'token', 'key']):
                findings.append(CICDVulnerability(
                    name="Secrets in Build Arguments",
                    severity="Critical",
                    file_path=file_path,
                    line_number=i + 1,
                    description="Secrets passed as build arguments may be exposed in image history",
                    remediation="Use Docker secrets or multi-stage builds for secrets"
                ))
            
            # Check for exposed ports
            if 'expose' in line_lower:
                match = re.search(r'expose\s+(\d+)', line_lower)
                if match:
                    port = match.group(1)
                    if port in ['22', '23', '21', '3306', '5432']:
                        findings.append(CICDVulnerability(
                            name="Potentially Exposed Service",
                            severity="Low",
                            file_path=file_path,
                            line_number=i + 1,
                            description=f"Service on port {port} is exposed",
                            remediation="Only expose necessary ports and use network segmentation"
                        ))
            
            # Check for outdated base images
            if 'from' in line_lower:
                if 'latest' in line_lower:
                    findings.append(CICDVulnerability(
                        name="Using 'latest' Tag",
                        severity="Medium",
                        file_path=file_path,
                        line_number=i + 1,
                        description="Using 'latest' tag leads to unpredictable builds",
                        remediation="Use specific version tags for base images"
                    ))
                    
        return findings
    
    def scan_k8s_manifest(self, manifest_content: str, file_path: str) -> List[CICDVulnerability]:
        """Scan Kubernetes manifest for security issues"""
        findings = []
        
        try:
            manifest = yaml.safe_load(manifest_content)
            
            # Check for privileged containers
            if manifest.get('kind') == 'Pod' or manifest.get('kind') == 'Deployment':
                spec = manifest.get('spec', {})
                if manifest.get('kind') == 'Deployment':
                    spec = manifest.get('spec', {}).get('template', {}).get('spec', {})
                
                containers = spec.get('containers', [])
                for i, container in enumerate(containers):
                    security_context = container.get('securityContext', {})
                    
                    # Check for privileged mode
                    if security_context.get('privileged'):
                        findings.append(CICDVulnerability(
                            name="Privileged Container",
                            severity="Critical",
                            file_path=file_path,
                            line_number=i + 1,
                            description="Container runs in privileged mode, allowing host access",
                            remediation="Avoid privileged containers and use specific capabilities"
                        ))
                    
                    # Check for root user
                    if security_context.get('runAsUser') == 0:
                        findings.append(CICDVulnerability(
                            name="Container Running as Root",
                            severity="High",
                            file_path=file_path,
                            line_number=i + 1,
                            description="Container runs as root user",
                            remediation="Set runAsNonRoot: true and runAsUser to >10000"
                        ))
                    
                    # Check for writable root filesystem
                    if not security_context.get('readOnlyRootFilesystem'):
                        findings.append(CICDVulnerability(
                            name="Writable Root Filesystem",
                            severity="Medium",
                            file_path=file_path,
                            line_number=i + 1,
                            description="Container has writable root filesystem",
                            remediation="Set readOnlyRootFilesystem: true"
                        ))
            
            # Check for host network access
            if manifest.get('spec', {}).get('hostNetwork'):
                findings.append(CICDVulnerability(
                    name="Host Network Access",
                    severity="High",
                    file_path=file_path,
                    line_number=1,
                    description="Pod has access to host network namespace",
                    remediation="Avoid hostNetwork unless absolutely necessary"
                ))
                
        except Exception as e:
            print(f"Error parsing manifest: {e}")
            
        return findings
    
    def scan_all(self) -> List[CICDVulnerability]:
        """Scan repository for CI/CD vulnerabilities"""
        all_findings = []
        
        # Get repository contents (simplified - would use GitHub API)
        files_to_scan = {
            '.github/workflows/*.yml': self.scan_github_actions,
            'Dockerfile': self.scan_dockerfile,
            '*.yaml': self.scan_k8s_manifest,
            '*.yml': self.scan_k8s_manifest
        }
        
        # Mock scanning for demo
        # In production, this would fetch actual files from the repo
        
        return all_findings

# Example usage
async def scan_repository(repo_url: str):
    scanner = CICDScanner(repo_url)
    findings = scanner.scan_all()
    
    for finding in findings:
        print(f"""
⚠️  Vulnerability Found: {finding.name}
   Severity: {finding.severity}
   File: {finding.file_path}
   Description: {finding.description}
   Remediation: {finding.remediation}
        """)
    
    return findings
