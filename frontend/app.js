// API Base URL
const API_BASE = 'http://localhost:8000';

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        
        // Update active nav item
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        // Show corresponding page
        const pageId = item.dataset.page;
        document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
        document.getElementById(`${pageId}-page`).classList.add('active');
        
        // Update page title
        document.getElementById('page-title').textContent = 
            pageId.charAt(0).toUpperCase() + pageId.slice(1);
    });
});

// Dashboard Charts
let vulnChart, scanChart;

async function loadDashboard() {
    try {
        // Fetch stats
        const stats = await fetchStats();
        document.getElementById('total-scans').textContent = stats.total_scans || 0;
        document.getElementById('total-vulns').textContent = stats.total_vulnerabilities || 0;
        document.getElementById('total-hosts').textContent = stats.total_hosts || 0;
        document.getElementById('active-scans').textContent = stats.active_scans || 0;
        
        // Initialize charts
        initCharts(stats);
    } catch (error) {
        console.error('Error loading dashboard:', error);
    }
}

function initCharts(stats) {
    // Vulnerability Chart
    const vulnCtx = document.getElementById('vuln-chart').getContext('2d');
    if (vulnChart) vulnChart.destroy();
    
    vulnChart = new Chart(vulnCtx, {
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
                backgroundColor: ['#ff4757', '#ff6b6b', '#ffaa00', '#00d68f'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#e0e0e0' }
                }
            }
        }
    });
    
    // Scan Timeline Chart
    const scanCtx = document.getElementById('scan-timeline').getContext('2d');
    if (scanChart) scanChart.destroy();
    
    scanChart = new Chart(scanCtx, {
        type: 'line',
        data: {
            labels: stats.scan_dates || ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [{
                label: 'Scans',
                data: stats.scan_counts || [0, 0, 0, 0, 0, 0, 0],
                borderColor: '#00ff9d',
                backgroundColor: 'rgba(0, 255, 157, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#e0e0e0' }
                }
            },
            scales: {
                x: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#e0e0e0' } },
                y: { grid: { color: 'rgba(255,255,255,0.1)' }, ticks: { color: '#e0e0e0' } }
            }
        }
    });
}

// Reconnaissance Functions
async function startRecon() {
    const target = document.getElementById('recon-target').value;
    if (!target) {
        alert('Please enter a target domain');
        return;
    }
    
    try {
        // Show loading state
        document.querySelectorAll('.results-list').forEach(list => {
            list.innerHTML = '<div class="result-item">Loading...</div>';
        });
        
        // Call recon endpoint
        const response = await fetch(`${API_BASE}/recon`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        
        const data = await response.json();
        
        // Update results
        displaySubdomains(data.subdomains || []);
        displayUrls(data.urls || []);
        displayParameters(data.parameters || []);
        displayDirectories(data.directories || []);
        displayTechnologies(data.technologies || []);
        
    } catch (error) {
        console.error('Error starting recon:', error);
        alert('Error starting reconnaissance');
    }
}

function displaySubdomains(subdomains) {
    const list = document.getElementById('subdomains-list');
    document.getElementById('subdomain-count').textContent = subdomains.length;
    
    list.innerHTML = subdomains.map(sub => `
        <div class="result-item">
            <i class="fas fa-globe"></i> ${sub}
        </div>
    `).join('');
}

function displayUrls(urls) {
    const list = document.getElementById('urls-list');
    document.getElementById('urls-count').textContent = urls.length;
    
    list.innerHTML = urls.map(url => `
        <div class="result-item">
            <i class="fas fa-link"></i> ${url}
        </div>
    `).join('');
}

function displayParameters(params) {
    const list = document.getElementById('parameters-list');
    document.getElementById('parameters-count').textContent = params.length;
    
    list.innerHTML = params.map(param => `
        <div class="result-item">
            <i class="fas fa-code"></i> ${param}
        </div>
    `).join('');
}

function displayDirectories(dirs) {
    const list = document.getElementById('directories-list');
    document.getElementById('directories-count').textContent = dirs.length;
    
    list.innerHTML = dirs.map(dir => `
        <div class="result-item">
            <i class="fas fa-folder"></i> ${dir}
        </div>
    `).join('');
}

function displayTechnologies(techs) {
    const list = document.getElementById('tech-list');
    document.getElementById('tech-count').textContent = techs.length;
    
    list.innerHTML = techs.map(tech => `
        <div class="result-item">
            <i class="fas fa-cube"></i> ${tech}
        </div>
    `).join('');
}

// Vulnerability Scan Functions
async function startVulnScan() {
    const target = document.getElementById('scan-target').value;
    const scanType = document.getElementById('scan-type').value;
    
    if (!target) {
        alert('Please enter a target');
        return;
    }
    
    // Show progress
    document.getElementById('scan-progress').style.display = 'block';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('scan-status').textContent = 'Starting scan...';
    
    try {
        // Start scan
        const response = await fetch(`${API_BASE}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: scanType })
        });
        
        const { scan_id } = await response.json();
        
        // Poll for results
        pollScanResults(scan_id);
        
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Error starting vulnerability scan');
        document.getElementById('scan-progress').style.display = 'none';
    }
}

async function pollScanResults(scanId) {
    let completed = false;
    let progress = 0;
    
    while (!completed) {
        try {
            const response = await fetch(`${API_BASE}/scan/${scanId}/status`);
            const data = await response.json();
            
            // Update progress
            progress = data.progress || progress;
            document.getElementById('progress-fill').style.width = `${progress}%`;
            document.getElementById('scan-status').textContent = data.status || 'Scanning...';
            
            if (data.completed) {
                completed = true;
                displayVulnerabilities(data.vulnerabilities || []);
                document.getElementById('scan-progress').style.display = 'none';
            }
            
            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, 2000));
            
        } catch (error) {
            console.error('Error polling scan results:', error);
            completed = true;
        }
    }
}

function displayVulnerabilities(vulns) {
    const container = document.getElementById('vuln-results');
    
    if (vulns.length === 0) {
        container.innerHTML = '<div class="result-item">No vulnerabilities found</div>';
        return;
    }
    
    container.innerHTML = vulns.map(vuln => `
        <div class="vuln-item ${vuln.severity.toLowerCase()}">
            <div class="vuln-header">
                <span class="vuln-name">${vuln.name}</span>
                <span class="vuln-severity ${vuln.severity.toLowerCase()}">${vuln.severity}</span>
            </div>
            <div class="vuln-description">${vuln.description || ''}</div>
            <div class="vuln-meta">
                <span><i class="fas fa-code"></i> CVE: ${vuln.cve_id || 'N/A'}</span>
                <span><i class="fas fa-star"></i> CVSS: ${vuln.cvss || 'N/A'}</span>
                <span><i class="fas fa-link"></i> ${vuln.location || ''}</span>
            </div>
        </div>
    `).join('');
}

// Tab Switching
function showTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    event.target.classList.add('active');
    
    // Show corresponding tab
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.getElementById(`${tabName}-tab`).classList.add('active');
}

// Export Functions
async function exportResults(type) {
    try {
        const response = await fetch(`${API_BASE}/export/${type}`);
        const blob = await response.blob();
        
        // Create download link
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${type}_results_${new Date().toISOString()}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
        
    } catch (error) {
        console.error('Error exporting results:', error);
        alert('Error exporting results');
    }
}

// Fetch Stats from Backend
async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        return await response.json();
    } catch (error) {
        console.error('Error fetching stats:', error);
        return {};
    }
}

// Initialize Dashboard on Load
document.addEventListener('DOMContentLoaded', () => {
    loadDashboard();
});

// Poll for updates every 30 seconds
setInterval(loadDashboard, 30000);
