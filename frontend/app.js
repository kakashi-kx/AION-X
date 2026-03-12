// API Base URL
const API_BASE = 'http://localhost:8000';

// Wait for DOM to be fully loaded before running any code
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM fully loaded - initializing AION-X dashboard');
    
    // Initialize navigation
    initializeNavigation();
    
    // Load dashboard data
    loadDashboard();
    
    // Set up periodic stats refresh (every 30 seconds)
    setInterval(loadDashboard, 30000);
});

// ==================== NAVIGATION ====================
function initializeNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    console.log(`Found ${navItems.length} navigation items`);
    
    if (navItems.length === 0) {
        console.error('No navigation items found! Check your HTML structure.');
        return;
    }
    
    navItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            
            const pageId = this.dataset.page;
            console.log('Navigating to:', pageId);
            
            if (!pageId) {
                console.error('No page-id found on nav item');
                return;
            }
            
            // Update active state on nav items
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
            
            // Hide all pages
            document.querySelectorAll('.page').forEach(page => {
                page.classList.remove('active');
            });
            
            // Show selected page
            const targetPage = document.getElementById(`${pageId}-page`);
            if (targetPage) {
                targetPage.classList.add('active');
                console.log(`Showing page: ${pageId}-page`);
            } else {
                console.error(`Page element #${pageId}-page not found`);
            }
            
            // Update page title
            const titleElement = document.getElementById('page-title');
            if (titleElement) {
                titleElement.textContent = pageId.charAt(0).toUpperCase() + pageId.slice(1);
            }
        });
    });
    
    // Trigger click on first nav item to show default page
    if (navItems.length > 0) {
        navItems[0].click();
    }
}

// ==================== DASHBOARD ====================
async function loadDashboard() {
    console.log('Loading dashboard stats...');
    
    try {
        const stats = await fetchStats();
        console.log('Dashboard stats:', stats);
        
        // Update stats cards
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

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching stats:', error);
        return {
            total_scans: 0,
            total_vulnerabilities: 0,
            total_hosts: 0,
            active_scans: 0,
            critical_vulns: 0,
            high_vulns: 0,
            medium_vulns: 0,
            low_vulns: 0,
            scan_dates: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            scan_counts: [0, 0, 0, 0, 0, 0, 0]
        };
    }
}

function initCharts(stats) {
    // Vulnerability Chart
    const vulnCtx = document.getElementById('vuln-chart');
    if (!vulnCtx) {
        console.error('vuln-chart element not found');
        return;
    }
    
    // Check if Chart is defined
    if (typeof Chart === 'undefined') {
        console.error('Chart.js not loaded');
        return;
    }
    
    // Destroy existing chart if it exists
    if (window.vulnChart) {
        window.vulnChart.destroy();
    }
    
    window.vulnChart = new Chart(vulnCtx.getContext('2d'), {
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
    const scanCtx = document.getElementById('scan-timeline');
    if (!scanCtx) {
        console.error('scan-timeline element not found');
        return;
    }
    
    if (window.scanChart) {
        window.scanChart.destroy();
    }
    
    window.scanChart = new Chart(scanCtx.getContext('2d'), {
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
                x: { 
                    grid: { color: 'rgba(255,255,255,0.1)' }, 
                    ticks: { color: '#e0e0e0' } 
                },
                y: { 
                    grid: { color: 'rgba(255,255,255,0.1)' }, 
                    ticks: { color: '#e0e0e0' } 
                }
            }
        }
    });
}

// ==================== RECONNAISSANCE ====================
async function startRecon() {
    const target = document.getElementById('recon-target').value;
    if (!target) {
        alert('Please enter a target domain');
        return;
    }
    
    console.log('Starting recon for target:', target);
    
    // Show loading state
    showLoadingState();
    
    try {
        console.log('Sending request to:', `${API_BASE}/recon`);
        
        const response = await fetch(`${API_BASE}/recon`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ target })
        });
        
        console.log('Response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Received data:', data);
        
        // Update results
        displaySubdomains(data.subdomains || []);
        displayUrls(data.urls || []);
        displayParameters(data.parameters || []);
        displayDirectories(data.directories || []);
        displayTechnologies(data.technologies || []);
        
    } catch (error) {
        console.error('Error starting recon:', error);
        showErrorState(error.message);
        alert('Error starting reconnaissance: ' + error.message);
    }
}

function showLoadingState() {
    const resultContainers = [
        'subdomains-list', 'urls-list', 'parameters-list', 
        'directories-list', 'tech-list'
    ];
    
    resultContainers.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = '<div class="result-item"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
        }
    });
    
    // Reset counts
    document.getElementById('subdomain-count').textContent = '0';
    document.getElementById('urls-count').textContent = '0';
    document.getElementById('parameters-count').textContent = '0';
    document.getElementById('directories-count').textContent = '0';
    document.getElementById('tech-count').textContent = '0';
}

function showErrorState(errorMessage) {
    const resultContainers = [
        'subdomains-list', 'urls-list', 'parameters-list', 
        'directories-list', 'tech-list'
    ];
    
    resultContainers.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.innerHTML = `<div class="result-item error">
                <i class="fas fa-exclamation-triangle"></i> Error: ${errorMessage}
            </div>`;
        }
    });
}

function displaySubdomains(subdomains) {
    console.log('Displaying subdomains:', subdomains.length);
    const list = document.getElementById('subdomains-list');
    const countSpan = document.getElementById('subdomain-count');
    
    if (!list) {
        console.error('subdomains-list element not found');
        return;
    }
    
    countSpan.textContent = subdomains.length;
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
    console.log('Displaying URLs:', urls.length);
    const list = document.getElementById('urls-list');
    const countSpan = document.getElementById('urls-count');
    
    if (!list) return;
    
    countSpan.textContent = urls.length;
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
    console.log('Displaying parameters:', params.length);
    const list = document.getElementById('parameters-list');
    const countSpan = document.getElementById('parameters-count');
    
    if (!list) return;
    
    countSpan.textContent = params.length;
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
    console.log('Displaying directories:', dirs.length);
    const list = document.getElementById('directories-list');
    const countSpan = document.getElementById('directories-count');
    
    if (!list) return;
    
    countSpan.textContent = dirs.length;
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
    console.log('Displaying technologies:', techs.length);
    const list = document.getElementById('tech-list');
    const countSpan = document.getElementById('tech-count');
    
    if (!list) return;
    
    countSpan.textContent = techs.length;
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

// ==================== TAB SWITCHING ====================
function showTab(tabName) {
    console.log('Switching to tab:', tabName);
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Find and activate the clicked button
    const activeBtn = Array.from(document.querySelectorAll('.tab-btn'))
        .find(btn => btn.textContent.toLowerCase().includes(tabName.toLowerCase()));
    
    if (activeBtn) {
        activeBtn.classList.add('active');
    }
    
    // Show corresponding tab content
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const targetTab = document.getElementById(`${tabName}-tab`);
    if (targetTab) {
        targetTab.classList.add('active');
    }
}

// ==================== EXPORT ====================
async function exportResults(type) {
    try {
        const response = await fetch(`${API_BASE}/export/${type}`);
        const blob = await response.blob();
        
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

// Make functions globally available for onclick events
window.startRecon = startRecon;
window.showTab = showTab;
window.exportResults = exportResults;
