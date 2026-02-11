// NileDefender - Web Vulnerability Scanner Application

// Configuration
const API_BASE = '/api';
let socket = null;
let currentScanId = null;
let allSubdomains = [];
let allEndpoints = [];

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadDashboardStats();
    loadRecentScans();
    loadRecentScans();
});

// Security: Escape HTML to prevent XSS
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// WebSocket
function initWebSocket() {
    const wsUrl = window.location.origin;
    socket = io(wsUrl);

    socket.on('connect', () => {
        document.getElementById('connection-dot').className = 'dot connected';
        document.getElementById('connection-text').textContent = 'Connected';
    });

    socket.on('disconnect', () => {
        document.getElementById('connection-dot').className = 'dot disconnected';
        document.getElementById('connection-text').textContent = 'Disconnected';
    });

    socket.on('scan_update', (data) => {
        console.log('Scan update:', data);
        if (currentScanId === data.scan_id) {
            loadScanDetails(data.scan_id);
        }
    });

    socket.on('scan_completed', (data) => {
        loadDashboardStats();
        loadRecentScans();
        if (currentScanId === data.scan_id) {
            loadScanDetails(data.scan_id);
        }
    });
}

// Navigation
function showPage(page) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));

    // Show selected page
    const pageEl = document.getElementById(`page-${page}`);
    if (pageEl) {
        pageEl.classList.add('active');
    }

    // Mark nav as active
    const navEl = document.getElementById(`nav-${page}`);
    if (navEl) {
        navEl.classList.add('active');
    }

    // Load page data
    if (page === 'dashboard') {
        loadDashboardStats();
        loadRecentScans();
    } else if (page === 'scans') {
        loadScans();
    }
}

function showDetailTab(tab) {
    document.querySelectorAll('.detail-tab-content').forEach(c => c.style.display = 'none');
    document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));

    document.getElementById(`detail-content-${tab}`).style.display = 'block';
    document.getElementById(`detail-tab-${tab}`).classList.add('active');
}

// Dashboard
async function loadDashboardStats() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/stats`);
        const data = await res.json();

        if (data.success) {
            document.getElementById('stat-total-scans').textContent = data.stats.total_scans;
            document.getElementById('stat-running-scans').textContent = data.stats.running_scans;
            document.getElementById('stat-subdomains').textContent = data.stats.total_subdomains;
            document.getElementById('stat-endpoints').textContent = data.stats.total_endpoints;
        }
    } catch (err) {
        console.error('Error loading stats:', err);
    }
}

async function loadRecentScans() {
    try {
        const res = await fetch(`${API_BASE}/scans`);
        const data = await res.json();

        const container = document.getElementById('recent-scans-list');

        if (data.success && data.scans.length > 0) {
            container.innerHTML = data.scans.slice(0, 5).map(scan => `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 16px; background: var(--bg-primary); border-radius: 12px; margin-bottom: 12px; cursor: pointer; transition: all 0.2s;" 
                     onclick="viewScan(${scan.id})" 
                     onmouseover="this.style.transform='translateX(4px)'" 
                     onmouseout="this.style.transform='none'">
                    <div>
                        <div style="font-weight: 600; margin-bottom: 4px;">${escapeHtml(scan.domain)}</div>
                        <div style="font-size: 12px; color: var(--text-muted);">
                            ${scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A'}
                        </div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <div style="text-align: right; font-size: 12px; color: var(--text-muted);">
                            <div>${scan.subdomain_count} subdomains</div>
                            <div>${scan.endpoint_count} endpoints</div>
                        </div>
                        <span class="badge badge-${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
                        <button class="btn-delete" onclick="deleteScan(${scan.id}, '${escapeHtml(scan.domain)}', event)" title="Delete scan">
                            🗑️
                        </button>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="icon">🔍</div>
                    <h4>No scans yet</h4>
                    <p>Start your first reconnaissance scan</p>
                </div>
            `;
        }
    } catch (err) {
        console.error('Error loading scans:', err);
    }
}

// Scans
async function loadScans() {
    try {
        const res = await fetch(`${API_BASE}/scans`);
        const data = await res.json();

        const container = document.getElementById('scans-list');

        if (data.success && data.scans.length > 0) {
            container.innerHTML = data.scans.map(scan => `
                <div class="card scan-card" onclick="viewScan(${scan.id})">
                    <div class="scan-card-header">
                        <h3>${escapeHtml(scan.domain)}</h3>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <span class="badge badge-${escapeHtml(scan.status)}">${escapeHtml(scan.status)}</span>
                            <button class="btn-delete" onclick="deleteScan(${scan.id}, '${escapeHtml(scan.domain)}', event)" title="Delete scan">
                                🗑️
                            </button>
                        </div>
                    </div>
                    <div class="scan-meta">
                        <span>Scan ID: ${scan.id}</span>
                        <span>${scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A'}</span>
                    </div>
                    <div class="scan-stats">
                        <div class="scan-stat">
                            <div class="value">${scan.subdomain_count}</div>
                            <div class="label">Subdomains</div>
                        </div>
                        <div class="scan-stat">
                            <div class="value">${scan.endpoint_count}</div>
                            <div class="label">Endpoints</div>
                        </div>
                        <div class="scan-stat">
                            <div class="value">0</div>
                            <div class="label">Vulns</div>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            container.innerHTML = `
                <div class="empty-state" style="grid-column: 1 / -1;">
                    <div class="icon">🔍</div>
                    <h4>No scans found</h4>
                    <p>Start a new scan to begin reconnaissance</p>
                </div>
            `;
        }
    } catch (err) {
        console.error('Error loading scans:', err);
    }
}

// View Scan Details
async function viewScan(scanId) {
    currentScanId = scanId;
    socket.emit('join_scan', { scan_id: scanId });

    // Show details page
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById('page-scan-details').classList.add('active');

    await loadScanDetails(scanId);
}

async function loadScanDetails(scanId) {
    try {
        // Load scan info
        const res = await fetch(`${API_BASE}/scans/${scanId}`);
        const data = await res.json();

        if (data.success) {
            const scan = data.scan.scan;
            document.getElementById('detail-domain').textContent = scan.domain; // textContent is safe
            document.getElementById('detail-scan-id').textContent = scan.id;
            document.getElementById('detail-date').textContent = scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A';

            const statusBadge = document.getElementById('detail-status');
            statusBadge.textContent = scan.status; // textContent is safe
            statusBadge.className = `badge badge-${escapeHtml(scan.status)}`;
        }

        // Load stats
        const statsRes = await fetch(`${API_BASE}/scans/${scanId}/stats`);
        const statsData = await statsRes.json();

        if (statsData.success) {
            document.getElementById('detail-subdomains').textContent = statsData.stats.total_subdomains;
            document.getElementById('detail-get').textContent = statsData.stats.get_endpoints;
            document.getElementById('detail-post').textContent = statsData.stats.post_endpoints;
        }

        // Load subdomains and endpoints
        await loadSubdomains(scanId);
        await loadEndpoints(scanId);

    } catch (err) {
        console.error('Error loading scan details:', err);
    }
}

async function loadSubdomains(scanId) {
    try {
        const res = await fetch(`${API_BASE}/scans/${scanId}/subdomains`);
        const data = await res.json();

        if (data.success) {
            allSubdomains = data.subdomains;
            renderSubdomains(allSubdomains);
        }
    } catch (err) {
        console.error('Error loading subdomains:', err);
    }
}

function renderSubdomains(subdomains) {
    const table = document.getElementById('subdomains-table');

    if (subdomains.length === 0) {
        table.innerHTML = `<tr><td colspan="3" class="empty-state"><div class="icon">🌐</div><h4>No subdomains found</h4></td></tr>`;
        return;
    }

    // All subdomains in DB are alive (we only save alive ones)
    table.innerHTML = subdomains.map(s => `
        <tr>
            <td style="font-weight: 500;">${escapeHtml(s.subdomain)}</td>
            <td>${escapeHtml(s.status_code) || '-'}</td>
            <td style="color: var(--text-muted); font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(s.title) || '-'}</td>
        </tr>
    `).join('');
}

// Filter function removed - all subdomains are alive now


async function loadEndpoints(scanId) {
    try {
        const res = await fetch(`${API_BASE}/scans/${scanId}/endpoints`);
        const data = await res.json();

        if (data.success) {
            allEndpoints = data.endpoints;
            renderEndpoints(allEndpoints);
        }
    } catch (err) {
        console.error('Error loading endpoints:', err);
    }
}

function renderEndpoints(endpoints) {
    const getTable = document.getElementById('get-endpoints-table');
    const postTable = document.getElementById('post-endpoints-table');

    const getEndpoints = endpoints.filter(e => e.method === 'GET');
    const postEndpoints = endpoints.filter(e => e.method === 'POST');

    // GET endpoints
    if (getEndpoints.length === 0) {
        getTable.innerHTML = `<tr><td colspan="4" class="empty-state"><div class="icon">🔗</div><h4>No GET endpoints</h4></td></tr>`;
    } else {
        getTable.innerHTML = getEndpoints.map(e => `
            <tr>
                <td><span class="badge badge-get">GET</span></td>
                <td class="url-cell">${escapeHtml(e.url)}</td>
                <td class="params-cell">${e.parameters ? escapeHtml(Object.keys(e.parameters).join(', ')) : '-'}</td>
                <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(e.source) || '-'}</td>
            </tr>
        `).join('');
    }

    // POST endpoints
    if (postEndpoints.length === 0) {
        postTable.innerHTML = `<tr><td colspan="4" class="empty-state"><div class="icon">📝</div><h4>No POST endpoints</h4></td></tr>`;
    } else {
        postTable.innerHTML = postEndpoints.map(e => `
            <tr>
                <td><span class="badge badge-post">POST</span></td>
                <td class="url-cell">${escapeHtml(e.url)}</td>
                <td class="params-cell">${e.body_params ? escapeHtml(Object.keys(e.body_params).join(', ')) : '-'}</td>
                <td style="color: var(--text-muted); font-size: 12px;">${e.form_details ? escapeHtml(JSON.stringify(e.form_details).substring(0, 50)) : '-'}</td>
            </tr>
        `).join('');
    }
}

function filterEndpoints(method, filter) {
    document.querySelectorAll(`#detail-content-${method}-endpoints .filter-pill`).forEach(p => p.classList.remove('active'));
    event.target.classList.add('active');

    let filtered = allEndpoints.filter(e => e.method === method.toUpperCase());

    if (filter === 'params') {
        filtered = filtered.filter(e => e.parameters || e.body_params);
    }

    if (method === 'get') {
        const table = document.getElementById('get-endpoints-table');
        table.innerHTML = filtered.map(e => `
            <tr>
                <td><span class="badge badge-get">GET</span></td>
                <td class="url-cell">${escapeHtml(e.url)}</td>
                <td class="params-cell">${e.parameters ? escapeHtml(Object.keys(e.parameters).join(', ')) : '-'}</td>
                <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(e.source) || '-'}</td>
            </tr>
        `).join('') || `<tr><td colspan="4">No endpoints found</td></tr>`;
    }
}

// (Scan mode toggle removed — backend auto-detects local vs remote)

// Modal
function showModal() {
    document.getElementById('scan-modal').classList.add('active');
}

function hideModal() {
    document.getElementById('scan-modal').classList.remove('active');
    // Clear form
    const targetInput = document.getElementById('scan-target');
    if (targetInput) targetInput.value = '';
    const passiveCheckbox = document.getElementById('scan-passive');
    if (passiveCheckbox) passiveCheckbox.checked = true;
    const activeCheckbox = document.getElementById('scan-active');
    if (activeCheckbox) activeCheckbox.checked = false;
    const crawlCheckbox = document.getElementById('scan-crawl');
    if (crawlCheckbox) crawlCheckbox.checked = true;
}

// Create Scan — unified: backend auto-detects local vs remote
async function createScan(event) {
    event.preventDefault();

    const target = document.getElementById('scan-target').value.trim();
    const passive = document.getElementById('scan-passive').checked;
    const active = document.getElementById('scan-active').checked;
    const crawl = document.getElementById('scan-crawl').checked;

    if (!target) {
        alert('Please enter a target.');
        return;
    }

    const body = {
        target: target,
        passive: passive,
        active: active,
        crawl: crawl
    };

    try {
        const res = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await res.json();

        if (data.success) {
            hideModal();
            loadDashboardStats();
            loadScans();
            viewScan(data.scan_id);
        } else {
            alert('Error: ' + data.error);
        }
    } catch (err) {
        alert('Error creating scan: ' + err.message);
    }
}

// Delete current scan from details page
function deleteCurrentScan() {
    if (currentScanId) {
        const domain = document.getElementById('detail-domain').textContent;
        deleteScan(currentScanId, domain);
    }
}

// Store pending delete info
let pendingDeleteScanId = null;
let pendingDeleteDomain = null;

// Show Delete Modal
function showDeleteModal(scanId, domain) {
    pendingDeleteScanId = scanId;
    pendingDeleteDomain = domain;
    document.getElementById('delete-scan-domain').textContent = domain; // textContent is safe
    document.getElementById('delete-modal').classList.add('active');
}

// Hide Delete Modal
function hideDeleteModal() {
    document.getElementById('delete-modal').classList.remove('active');
    pendingDeleteScanId = null;
    pendingDeleteDomain = null;
}

// Delete Scan - Show confirmation modal
function deleteScan(scanId, domain, event) {
    // Stop event propagation to prevent triggering card click
    if (event) {
        event.stopPropagation();
    }

    // Show the beautiful custom delete modal
    showDeleteModal(scanId, domain);
}

// Confirm Delete Scan - Called when user clicks Delete button in modal
async function confirmDeleteScan() {
    if (!pendingDeleteScanId) {
        hideDeleteModal();
        return;
    }

    const scanId = pendingDeleteScanId;

    try {
        const res = await fetch(`${API_BASE}/scans/${scanId}`, {
            method: 'DELETE'
        });

        const data = await res.json();

        if (data.success) {
            // Hide modal first
            hideDeleteModal();

            // Refresh the UI
            loadDashboardStats();
            loadRecentScans();
            loadScans();

            // If we're on the scan details page, go back to scans
            if (currentScanId === scanId) {
                currentScanId = null;
                showPage('scans');
            }

            // Show success notification
            showNotification('Scan deleted successfully!', 'success');
        } else {
            hideDeleteModal();
            showNotification('Error deleting scan: ' + data.error, 'error');
        }
    } catch (err) {
        hideDeleteModal();
        showNotification('Error deleting scan: ' + err.message, 'error');
    }
}

// Show notification toast
function showNotification(message, type = 'info') {
    // Remove existing notification if any
    const existing = document.querySelector('.notification-toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `notification-toast notification-${type}`;
    toast.innerHTML = `
        <span class="notification-icon">${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span>
        <span class="notification-message">${escapeHtml(message)}</span>
    `;
    document.body.appendChild(toast);

    // Trigger animation
    setTimeout(() => toast.classList.add('show'), 10);

    // Auto remove after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Close modal on overlay click
document.getElementById('scan-modal').addEventListener('click', function (e) {
    if (e.target === this) {
        hideModal();
    }
});

// Close delete modal on overlay click
document.getElementById('delete-modal').addEventListener('click', function (e) {
    if (e.target === this) {
        hideDeleteModal();
    }
});
