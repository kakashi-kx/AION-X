// ==================== CONFIGURATION ====================
const API_BASE = '';  // Empty for relative URLs through proxy
let currentScanId = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('🚀 AION-X 3.0 - AI Security Platform Initializing...');
    showNotification('AION-X AI Platform Ready', 'success');
    
    initializeNavigation();
    loadDashboard();
    loadScanHistory();
    
    // Set up periodic updates
    setInterval(loadDashboard, 30000);
    setInterval(loadScanHistory, 60000);
});

// ==================== NOTIFICATION SYSTEM ====================
function showNotification(message, type = 'info') {
    Swal.fire({
        title: message,
        icon: type,
        toast: true,
        position: 'top-end',
        showConfirmButton: false,
        timer: 3000,
        timerProgressBar: true,
        background: 'var(--bg-card)',
        color: 'white'
    });
}

// ==================== NAVIGATION ====================
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            const pageId = this.dataset.page;
            
            // Update active state
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            // Show selected page
            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
            });
            document.getElementById(`${pageId}-page`).classList.add('active');
            
            // Update page title
            document.getElementById('page-title').textContent = 
                this.querySelector('span').textContent;
            
            // Trigger page-specific loading
            if (pageId === 'dashboard') loadDashboard();
            if (pageId === 'reports') loadScanHistory();
        });
    });
}

// ==================== DASHBOARD ====================
async function loadDashboard() {
    try {
        const stats = await fetchStats();
        updateDashboardStats(stats);
        updateCharts(stats);
        updateRecentInsights();
    } catch (error) {
        console.error('Dashboard error:', error);
    }
}

async function fetchStats() {
    const response = await fetch('/api/stats');
    return await response.json();
}

function updateDashboardStats(stats) {
    // Main stats
    document.getElementById('total-scans').textContent = stats.total_scans || 0;
    document.getElementById('total-vulns').textContent = stats.total_vulnerabilities || 0;
    document.getElementById('total-hosts').textContent = stats.total_hosts || 0;
    document.getElementById('active-scans').textContent = stats.active_scans || 0;
    
    // Mini stats in sidebar
    document.getElementById('total-scans-mini').textContent = stats.total_scans || 0;
    document.getElementById('total-vulns-mini').textContent = stats.total_vulnerabilities || 0;
}

function updateCharts(stats) {
    // Vulnerability Chart
    const vulnCtx = document.getElementById('vuln-chart');
    if (vulnCtx && window.vulnChart) window.vulnChart.destroy();
    
    if (vulnCtx) {
        window.vulnChart = new Chart(vulnCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [
                        stats.critical_vulns || 0,
                        stats.high_vulns || 0,
                        stats.medium_vulns || 0,
                        stats.low_vulns || 0
                    ],
                    backgroundColor: ['#ef4444', '#ff6b6b', '#f59e0b', '#10b981'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: 'white' } }
                }
            }
        });
    }
    
    // Timeline Chart
    const timelineCtx = document.getElementById('scan-timeline');
    if (timelineCtx && window.timelineChart) window.timelineChart.destroy();
    
    if (timelineCtx) {
        window.timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Scans',
                    data: stats.scan_counts || [0, 0, 0, 0, 0, 0, 0],
                    borderColor: '#8b5cf6',
                    backgroundColor: 'rgba(139, 92, 246, 0.1)',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: 'white' } }
                },
                scales: {
                    x: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: 'white' } },
                    y: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: 'white' } }
                }
            }
        });
    }
}

// ==================== RECONNAISSANCE ====================
async function startRecon() {
    const target = document.getElementById('recon-target').value;
    if (!target) {
        showNotification('Please enter a target domain', 'warning');
        return;
    }
    
    showLoadingState();
    
    try {
        const response = await fetch('/api/recon', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        
        displaySubdomains(data.subdomains || []);
        displayUrls(data.urls || []);
        displayParameters(data.parameters || []);
        displayDirectories(data.directories || []);
        displayTechnologies(data.technologies || []);
        
        showNotification(`Recon completed for ${target}`, 'success');
        
    } catch (error) {
        showNotification('Recon failed: ' + error.message, 'error');
        showErrorState(error.message);
    }
}

// ==================== AI BUGREAPER ====================
async function startAIScan() {
    const target = document.getElementById('ai-target').value;
    const depth = document.getElementById('ai-depth').value;
    
    if (!target) {
        showNotification('Please enter a target', 'warning');
        return;
    }
    
    // Show progress
    document.getElementById('ai-progress').style.display = 'block';
    document.getElementById('ai-status').textContent = 'Initializing AI Engine...';
    
    try {
        const response = await fetch('/api/ai-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_depth: depth })
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        
        // Animate progress
        let progress = 0;
        const interval = setInterval(() => {
            progress += 10;
            document.getElementById('ai-progress-fill').style.width = progress + '%';
            if (progress >= 100) {
                clearInterval(interval);
                displayAIResults(data);
                showNotification('AI Scan Complete!', 'success');
            }
        }, 300);
        
    } catch (error) {
        document.getElementById('ai-progress').style.display = 'none';
        showNotification('AI Scan failed: ' + error.message, 'error');
    }
}

function displayAIResults(data) {
    const container = document.getElementById('ai-results');
    document.getElementById('ai-progress').style.display = 'none';
    
    let html = `
        <div class="results-summary">
            <h4>🔍 AI Analysis Results</h4>
            <div class="stats-mini">
                <span class="badge critical">Critical: ${data.critical || 0}</span>
                <span class="badge high">High: ${data.high || 0}</span>
                <span class="badge medium">Medium: ${data.medium || 0}</span>
                <span class="badge low">Low: ${data.low || 0}</span>
            </div>
        </div>
    `;
    
    if (data.findings && data.findings.length > 0) {
        data.findings.forEach(finding => {
            html += `
                <div class="vuln-item ${finding.severity?.toLowerCase() || 'info'}">
                    <div class="vuln-header">
                        <span class="vuln-name">${finding.name || 'Unknown'}</span>
                        <span class="vuln-severity ${finding.severity?.toLowerCase()}">${finding.severity || 'INFO'}</span>
                    </div>
                    <div class="vuln-description">${finding.description || 'No description'}</div>
                    <div class="vuln-meta">
                        <span><i class="fas fa-code"></i> ${finding.cwe || 'N/A'}</span>
                        <span><i class="fas fa-star"></i> CVSS: ${finding.cvss_score || 'N/A'}</span>
                        <span><i class="fas fa-check-circle"></i> Confidence: ${Math.round(finding.confidence * 100)}%</span>
                    </div>
                </div>
            `;
        });
    } else {
        html += '<p class="no-results">No vulnerabilities found</p>';
    }
    
    container.innerHTML = html;
}

// ==================== API SCANNER ====================
async function startAPIScan() {
    const target = document.getElementById('api-target').value;
    const apiBase = document.getElementById('api-base').value;
    
    if (!target) {
        showNotification('Please enter an API target', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/api-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, api_base: apiBase })
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        displayAPIResults(data);
        showNotification('API Scan Complete!', 'success');
        
    } catch (error) {
        showNotification('API Scan failed: ' + error.message, 'error');
    }
}

function displayAPIResults(data) {
    const container = document.getElementById('api-results');
    
    let html = '<div class="results-summary"><h4>🔌 API Security Scan Results</h4>';
    
    if (data.endpoints_discovered && data.endpoints_discovered.length > 0) {
        html += '<h5>Discovered Endpoints:</h5><ul>';
        data.endpoints_discovered.forEach(ep => {
            html += `<li><i class="fas fa-link"></i> ${ep}</li>`;
        });
        html += '</ul>';
    }
    
    if (data.findings && data.findings.length > 0) {
        html += '<h5>Vulnerabilities:</h5>';
        data.findings.forEach(f => {
            html += `
                <div class="vuln-item ${f.severity?.toLowerCase()}">
                    <div class="vuln-header">
                        <span class="vuln-name">${f.name}</span>
                        <span class="vuln-severity ${f.severity?.toLowerCase()}">${f.category || 'API'}</span>
                    </div>
                    <div class="vuln-description">${f.description}</div>
                </div>
            `;
        });
    }
    
    container.innerHTML = html;
}

// ==================== CI/CD SCANNER ====================
async function startCICDScan() {
    const repoUrl = document.getElementById('repo-url').value;
    const branch = document.getElementById('repo-branch').value;
    
    if (!repoUrl) {
        showNotification('Please enter a repository URL', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/cicd-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ repo_url: repoUrl, branch: branch })
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        displayCICDResults(data);
        showNotification('CI/CD Scan Complete!', 'success');
        
    } catch (error) {
        showNotification('CI/CD Scan failed: ' + error.message, 'error');
    }
}

function displayCICDResults(data) {
    const container = document.getElementById('cicd-results');
    
    let html = `
        <div class="results-summary">
            <h4>🔄 CI/CD Security Scan Results</h4>
            <div class="stats-mini">
                <span class="badge critical">Critical: ${data.critical || 0}</span>
                <span class="badge high">High: ${data.high || 0}</span>
                <span class="badge medium">Medium: ${data.medium || 0}</span>
                <span class="badge low">Low: ${data.low || 0}</span>
            </div>
        </div>
    `;
    
    if (data.findings && data.findings.length > 0) {
        data.findings.forEach(f => {
            html += `
                <div class="vuln-item ${f.severity?.toLowerCase()}">
                    <div class="vuln-header">
                        <span class="vuln-name">${f.name}</span>
                        <span class="vuln-severity ${f.severity?.toLowerCase()}">${f.severity}</span>
                    </div>
                    <div class="vuln-description">${f.description}</div>
                    <div class="vuln-meta">
                        <span><i class="fas fa-file"></i> ${f.file_path || 'N/A'}</span>
                        <span><i class="fas fa-hashtag"></i> Line: ${f.line_number || 'N/A'}</span>
                    </div>
                </div>
            `;
        });
    } else {
        html += '<p class="no-results">No issues found</p>';
    }
    
    container.innerHTML = html;
}

// ==================== REPORTS ====================
async function loadScanHistory() {
    try {
        const response = await fetch('/api/scans');
        const data = await response.json();
        
        const historyEl = document.getElementById('scan-history');
        if (!historyEl) return;
        
        let html = '';
        data.completed.slice(-5).reverse().forEach(scanId => {
            html += `
                <div class="scan-history-item" onclick="viewScan('${scanId}')">
                    <i class="fas fa-file-alt"></i>
                    <div>
                        <strong>Scan ${scanId.slice(0,8)}</strong>
                        <small>Completed</small>
                    </div>
                </div>
            `;
        });
        
        historyEl.innerHTML = html || '<p>No scans yet</p>';
        
    } catch (error) {
        console.error('Failed to load scan history:', error);
    }
}

async function generateReport(format) {
    if (!currentScanId) {
        // Get latest scan
        try {
            const response = await fetch('/api/scans');
            const data = await response.json();
            if (data.completed.length > 0) {
                currentScanId = data.completed[data.completed.length - 1];
            } else {
                showNotification('No scans available', 'warning');
                return;
            }
        } catch (error) {
            showNotification('Failed to get scan data', 'error');
            return;
        }
    }
    
    try {
        const response = await fetch(`/api/generate-report/${currentScanId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ format, include_ai_analysis: true })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `report_${currentScanId}.${format}`;
            a.click();
            showNotification(`Report generated: ${format.toUpperCase()}`, 'success');
        }
    } catch (error) {
        showNotification('Report generation failed', 'error');
    }
}

async function exportJSON() {
    if (!currentScanId) {
        showNotification('No scan selected', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`/api/export/${currentScanId}?format=json`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${currentScanId}.json`;
        a.click();
    } catch (error) {
        showNotification('Export failed', 'error');
    }
}

// ==================== BUG BOUNTY ====================
async function submitToPlatform(platform) {
    if (!currentScanId) {
        showNotification('No scan selected', 'warning');
        return;
    }
    
    // Get the first critical finding as example
    try {
        const response = await fetch(`/api/scan/${currentScanId}/status`);
        const data = await response.json();
        
        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            showNotification('No vulnerabilities to submit', 'warning');
            return;
        }
        
        const vuln = data.vulnerabilities[0];
        
        const submitResponse = await fetch('/api/submit-to-bugbounty', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                vulnerability: vuln,
                platform: platform,
                program_id: 'example-program'
            })
        });
        
        if (submitResponse.ok) {
            showNotification(`Submitted to ${platform} successfully!`, 'success');
        }
    } catch (error) {
        showNotification('Submission failed', 'error');
    }
}

function submitManual() {
    const desc = document.getElementById('vuln-desc').value;
    const severity = document.getElementById('vuln-severity').value;
    
    if (!desc || !severity) {
        showNotification('Please fill all fields', 'warning');
        return;
    }
    
    showNotification('Manual submission saved', 'success');
}

// ==================== DISPLAY FUNCTIONS ====================
function displaySubdomains(subdomains) {
    const list = document.getElementById('subdomains-list');
    const count = document.getElementById('subdomain-count');
    const countDisplay = document.getElementById('subdomain-count-display');
    
    if (count) count.textContent = subdomains.length;
    if (countDisplay) countDisplay.textContent = subdomains.length;
    
    if (!list) return;
    
    list.innerHTML = '';
    if (subdomains.length === 0) {
        list.innerHTML = '<div class="result-item">No subdomains found</div>';
        return;
    }
    
    subdomains.forEach(sub => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = `<i class="fas fa-globe"></i> ${sub}`;
        list.appendChild(div);
    });
}

function displayUrls(urls) {
    const list = document.getElementById('urls-list');
    const count = document.getElementById('urls-count');
    const countDisplay = document.getElementById('urls-count-display');
    
    if (count) count.textContent = urls.length;
    if (countDisplay) countDisplay.textContent = urls.length;
    if (!list) return;
    
    list.innerHTML = '';
    if (urls.length === 0) {
        list.innerHTML = '<div class="result-item">No URLs found</div>';
        return;
    }
    
    urls.forEach(url => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = `<i class="fas fa-link"></i> ${url}`;
        list.appendChild(div);
    });
}

function displayParameters(params) {
    const list = document.getElementById('parameters-list');
    const count = document.getElementById('parameters-count');
    const countDisplay = document.getElementById('parameters-count-display');
    
    if (count) count.textContent = params.length;
    if (countDisplay) countDisplay.textContent = params.length;
    if (!list) return;
    
    list.innerHTML = '';
    if (params.length === 0) {
        list.innerHTML = '<div class="result-item">No parameters found</div>';
        return;
    }
    
    params.forEach(param => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = `<i class="fas fa-code"></i> ${param}`;
        list.appendChild(div);
    });
}

function displayDirectories(dirs) {
    const list = document.getElementById('directories-list');
    const count = document.getElementById('directories-count');
    const countDisplay = document.getElementById('directories-count-display');
    
    if (count) count.textContent = dirs.length;
    if (countDisplay) countDisplay.textContent = dirs.length;
    if (!list) return;
    
    list.innerHTML = '';
    if (dirs.length === 0) {
        list.innerHTML = '<div class="result-item">No directories found</div>';
        return;
    }
    
    dirs.forEach(dir => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = `<i class="fas fa-folder"></i> ${dir}`;
        list.appendChild(div);
    });
}

function displayTechnologies(techs) {
    const list = document.getElementById('tech-list');
    const count = document.getElementById('tech-count');
    const countDisplay = document.getElementById('tech-count-display');
    
    if (count) count.textContent = techs.length;
    if (countDisplay) countDisplay.textContent = techs.length;
    if (!list) return;
    
    list.innerHTML = '';
    if (techs.length === 0) {
        list.innerHTML = '<div class="result-item">No technologies detected</div>';
        return;
    }
    
    techs.forEach(tech => {
        const div = document.createElement('div');
        div.className = 'result-item';
        div.innerHTML = `<i class="fas fa-cube"></i> ${tech}`;
        list.appendChild(div);
    });
}

// ==================== UTILITY FUNCTIONS ====================
function showLoadingState() {
    const lists = ['subdomains-list', 'urls-list', 'parameters-list', 'directories-list', 'tech-list'];
    lists.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<div class="result-item"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
    });
}

function showErrorState(message) {
    const lists = ['subdomains-list', 'urls-list', 'parameters-list', 'directories-list', 'tech-list'];
    lists.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = `<div class="result-item error"><i class="fas fa-exclamation-triangle"></i> ${message}</div>`;
    });
}

function showTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(
        btn => btn.textContent.toLowerCase().includes(tabName.toLowerCase())
    );
    if (activeBtn) activeBtn.classList.add('active');
    
    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) targetTab.classList.add('active');
}

function viewScan(scanId) {
    currentScanId = scanId;
    showNotification(`Viewing scan: ${scanId.slice(0,8)}`, 'info');
}

function updateRecentInsights() {
    const insightsEl = document.getElementById('recent-insights');
    if (!insightsEl) return;
    
    insightsEl.innerHTML = `
        <div class="activity-item">
            <i class="fas fa-robot"></i>
            <div class="activity-content">
                <strong>AI Analysis Complete</strong>
                <p>System ready for new scans</p>
                <small>Just now</small>
            </div>
        </div>
    `;
}

// ==================== EXPORT ====================
async function exportResults(type) {
    try {
        const response = await fetch(`/api/export/${type}`);
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${type}_results_${new Date().toISOString()}.json`;
        a.click();
        showNotification(`${type} exported successfully`, 'success');
    } catch (error) {
        showNotification('Export failed', 'error');
    }
}

// ==================== MAKE FUNCTIONS GLOBAL ====================
window.startRecon = startRecon;
window.startAIScan = startAIScan;
window.startAPIScan = startAPIScan;
window.startCICDScan = startCICDScan;
window.generateReport = generateReport;
window.exportJSON = exportJSON;
window.submitToPlatform = submitToPlatform;
window.submitManual = submitManual;
window.showTab = showTab;
window.exportResults = exportResults;
window.viewScan = viewScan;
