// NileDefender - Web Vulnerability Scanner Application

// Configuration
const API_BASE = '/api';
let socket = null;
let currentScanId = null;
let currentVulnScanId = null;
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
        // Update terminal log for vulnscan page
        if (currentVulnScanId === data.scan_id && (data.phase === 'vuln_scan' || data.phase === 'recon')) {
            appendToTerminal(data.message);
        }
    });

    socket.on('scan_completed', (data) => {
        loadDashboardStats();
        loadRecentScans();
        if (currentScanId === data.scan_id) {
            loadScanDetails(data.scan_id);
        }
    });

    socket.on('vulnscan_completed', (data) => {
        loadDashboardStats();
        loadRecentScans();
        if (currentScanId === data.scan_id) {
            loadScanDetails(data.scan_id);
            loadVulnerabilities(data.scan_id);
        }
    });

    socket.on('scan_error', (data) => {
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
    } else if (page === 'subdomains') {
        loadAllSubdomains();
    } else if (page === 'endpoints') {
        loadAllEndpoints();
    } else if (page === 'vulnerabilities') {
        loadAllVulnerabilities();
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
            document.getElementById('stat-vulnerabilities').textContent = data.stats.total_vulnerabilities || 0;
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
                            <div>${scan.vulnerability_count || 0} vulns</div>
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
                            <div class="value">${scan.vulnerability_count || 0}</div>
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
            document.getElementById('detail-domain').textContent = scan.domain;
            document.getElementById('detail-scan-id').textContent = scan.id;
            document.getElementById('detail-date').textContent = scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A';

            const statusBadge = document.getElementById('detail-status');
            statusBadge.textContent = scan.status;
            statusBadge.className = `badge badge-${escapeHtml(scan.status)}`;


        }

        // Load stats
        const statsRes = await fetch(`${API_BASE}/scans/${scanId}/stats`);
        const statsData = await statsRes.json();

        if (statsData.success) {
            document.getElementById('detail-subdomains').textContent = statsData.stats.total_subdomains;
            document.getElementById('detail-get').textContent = statsData.stats.get_endpoints;
            document.getElementById('detail-post').textContent = statsData.stats.post_endpoints;
            const vulnCountEl = document.getElementById('detail-vulns');
            if (vulnCountEl) vulnCountEl.textContent = statsData.stats.vulnerability_count || 0;
        }

        // Load subdomains, endpoints, and vulnerabilities
        await loadSubdomains(scanId);
        await loadEndpoints(scanId);
        await loadVulnerabilities(scanId);

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

// Modal — Unified (Recon + Vulnerability Scan)
let modalScanType = 'recon';  // 'recon' or 'vulnscan'
let modalVulnMode = 'full';   // 'full' or 'custom'
let modalSelectedExistingScanId = null;
let modalExistingScansDismissed = false;
let modalFreshScanRequested = false;
let modalSearchTimeout = null;

function showModal() {
    document.getElementById('scan-modal').classList.add('active');
    setModalScanType('recon');
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
    // Reset vuln scan state
    modalSelectedExistingScanId = null;
    modalExistingScansDismissed = false;
    modalFreshScanRequested = false;
    modalVulnMode = 'full';
    hideModalExistingScansBanner();
    // Reset submit button
    const btn = document.getElementById('scan-submit-btn');
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = 'Start Scan';
    }
}

function setModalScanType(type) {
    modalScanType = type;
    document.getElementById('modal-type-recon').classList.toggle('active', type === 'recon');
    document.getElementById('modal-type-vulnscan').classList.toggle('active', type === 'vulnscan');
    document.getElementById('modal-recon-panel').style.display = type === 'recon' ? 'block' : 'none';
    document.getElementById('modal-vulnscan-panel').style.display = type === 'vulnscan' ? 'block' : 'none';
    // Reset existing scans lookup when switching
    modalSelectedExistingScanId = null;
    modalExistingScansDismissed = false;
    hideModalExistingScansBanner();
    // If switching to vulnscan, check for existing scans
    if (type === 'vulnscan') {
        const target = document.getElementById('scan-target').value.trim();
        if (target.length >= 3) checkModalExistingScans(target);
    }
}

function setModalVulnMode(mode) {
    modalVulnMode = mode;
    document.getElementById('modal-mode-full').classList.toggle('active', mode === 'full');
    document.getElementById('modal-mode-custom').classList.toggle('active', mode === 'custom');
    document.getElementById('modal-vulnscan-modules').style.display = mode === 'custom' ? 'block' : 'none';
}

function onModalTargetInput() {
    if (modalScanType !== 'vulnscan') return;
    modalExistingScansDismissed = false;
    clearTimeout(modalSearchTimeout);
    const target = document.getElementById('scan-target').value.trim();
    modalSearchTimeout = setTimeout(() => checkModalExistingScans(target), 400);
}

async function checkModalExistingScans(target) {
    if (!target || target.length < 3 || modalExistingScansDismissed) {
        hideModalExistingScansBanner();
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/scans/search?target=${encodeURIComponent(target)}`);
        const data = await res.json();
        if (data.success && data.scans.length > 0) {
            showModalExistingScansBanner(data.scans);
        } else {
            hideModalExistingScansBanner();
        }
    } catch (err) {
        console.error('Error checking existing scans:', err);
        hideModalExistingScansBanner();
    }
}

function showModalExistingScansBanner(scans) {
    const banner = document.getElementById('modal-existing-scans-banner');
    const select = document.getElementById('modal-existing-scan-select');
    select.innerHTML = scans.map(s => {
        const date = s.scan_date ? new Date(s.scan_date).toLocaleDateString() : 'N/A';
        return `<option value="${s.id}">Scan #${s.id} — ${escapeHtml(s.domain)} (${s.endpoint_count} endpoints, ${date})</option>`;
    }).join('') + `<option value="new">🔄 Scan Fresh (new crawl)</option>`;
    modalSelectedExistingScanId = scans[0].id;
    select.value = scans[0].id;
    select.onchange = function () {
        if (this.value === 'new') {
            modalSelectedExistingScanId = null;
            modalFreshScanRequested = true;
        } else {
            modalSelectedExistingScanId = parseInt(this.value);
            modalFreshScanRequested = false;
        }
    };
    banner.style.display = 'block';
}

function hideModalExistingScansBanner() {
    const banner = document.getElementById('modal-existing-scans-banner');
    if (banner) banner.style.display = 'none';
    modalSelectedExistingScanId = null;
}

function dismissModalExistingScans() {
    modalExistingScansDismissed = true;
    hideModalExistingScansBanner();
}

// Create Scan — unified: handles both Recon and Vulnerability scan from one modal
async function createScan(event) {
    event.preventDefault();

    const target = document.getElementById('scan-target').value.trim();
    if (!target) {
        alert('Please enter a target.');
        return;
    }

    const btn = document.getElementById('scan-submit-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-small"></span> Starting...';

    try {
        // ===== RECON SCAN =====
        if (modalScanType === 'recon') {
            const passive = document.getElementById('scan-passive').checked;
            const active = document.getElementById('scan-active').checked;
            const crawl = document.getElementById('scan-crawl').checked;

            const res = await fetch(`${API_BASE}/scans`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, passive, active, crawl })
            });
            const data = await res.json();

            if (data.success) {
                hideModal();
                loadDashboardStats();
                loadScans();
                viewScan(data.scan_id);
            } else {
                alert('Error: ' + data.error);
                btn.disabled = false;
                btn.innerHTML = 'Start Scan';
            }
            return;
        }

        // ===== VULNERABILITY SCAN =====
        // Get selected modules
        const modules = [];
        if (modalVulnMode === 'full') {
            modules.push('sqli');
            modules.push('pt');
        } else {
            if (document.getElementById('modal-mod-sqli').checked) modules.push('sqli');
            if (document.getElementById('modal-mod-pt').checked) modules.push('pt');
        }
        if (modules.length === 0) {
            alert('Please select at least one vulnerability module.');
            btn.disabled = false;
            btn.innerHTML = 'Start Scan';
            return;
        }

        // Close modal and navigate to scan details
        // Save state BEFORE hideModal() resets everything to defaults
        const selectedExistingScanId = modalSelectedExistingScanId;
        const freshScanRequested = modalFreshScanRequested;
        hideModal();

        // === PATH A: Use existing scan (skip crawling) ===
        if (selectedExistingScanId) {
            const scanId = selectedExistingScanId;
            currentVulnScanId = scanId;

            // Join WebSocket room
            socket.emit('join_scan', { scan_id: scanId });

            // Launch vulnerability scan directly
            const vulnRes = await fetch(`${API_BASE}/scans/${scanId}/vulnscan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scan_type: modalVulnMode, modules })
            });
            const vulnData = await vulnRes.json();

            if (!vulnData.success && vulnRes.status !== 409) {
                alert('❌ ' + vulnData.error);
            }

            // Navigate to scan details
            currentScanId = scanId;
            viewScan(scanId);
            return;
        }

        // === PATH B: New scan (auto-crawl + vulnscan under one scan ID) ===
        // fresh=true when user explicitly chose "Scan Fresh" from the dropdown
        const createRes = await fetch(`${API_BASE}/vulnscan/start`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: modalVulnMode, modules, fresh: freshScanRequested })
        });
        const createData = await createRes.json();

        if (!createData.success) {
            alert('❌ Failed: ' + createData.error);
            return;
        }

        const scanId = createData.scan_id;
        currentVulnScanId = scanId;
        currentScanId = scanId;
        socket.emit('join_scan', { scan_id: scanId });

        // Navigate to scan details — data populates as scan progresses
        viewScan(scanId);

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

// ============================================================================
// DELETE ALL SCANS
// ============================================================================

// Show Delete All Modal
function deleteAllScans() {
    // Fetch current scan count to show in modal
    fetch(`${API_BASE}/scans`)
        .then(res => res.json())
        .then(data => {
            if (data.success && data.scans.length > 0) {
                document.getElementById('delete-all-count').textContent = data.scans.length;
                document.getElementById('delete-all-modal').classList.add('active');
            } else {
                showNotification('No scans to delete.', 'info');
            }
        })
        .catch(() => {
            // Still show modal even if count fetch fails
            document.getElementById('delete-all-count').textContent = 'all';
            document.getElementById('delete-all-modal').classList.add('active');
        });
}

// Hide Delete All Modal
function hideDeleteAllModal() {
    document.getElementById('delete-all-modal').classList.remove('active');
}

// Confirm Delete All Scans
async function confirmDeleteAllScans() {
    try {
        const res = await fetch(`${API_BASE}/scans/all`, {
            method: 'DELETE'
        });

        const data = await res.json();

        if (data.success) {
            hideDeleteAllModal();

            // Reset current scan view
            currentScanId = null;

            // Refresh everything
            loadDashboardStats();
            loadRecentScans();
            loadScans();

            // Go back to dashboard
            showPage('dashboard');

            showNotification(`${data.deleted_count} scan(s) deleted successfully!`, 'success');
        } else {
            hideDeleteAllModal();
            showNotification('Error: ' + data.error, 'error');
        }
    } catch (err) {
        hideDeleteAllModal();
        showNotification('Error deleting scans: ' + err.message, 'error');
    }
}

// Close delete-all modal on overlay click
document.getElementById('delete-all-modal').addEventListener('click', function (e) {
    if (e.target === this) {
        hideDeleteAllModal();
    }
});

// ============================================================================
// VULNERABILITY RESULTS (loaded in scan details Vulnerabilities tab)
// ============================================================================

async function loadVulnerabilities(scanId) {
    try {
        const res = await fetch(`${API_BASE}/scans/${scanId}/vulnerabilities`);
        const data = await res.json();

        const container = document.getElementById('detail-vuln-content');
        if (!container) return;

        if (data.success && data.vulnerabilities.length > 0) {
            // Count by severity
            const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            data.vulnerabilities.forEach(v => {
                if (counts[v.severity] !== undefined) counts[v.severity]++;
            });

            container.innerHTML = `
                <div class="vulnscan-results-header" style="margin-bottom: 16px;">
                    <div class="result-stats">
                        <span class="result-stat critical">${counts.Critical} Critical</span>
                        <span class="result-stat high">${counts.High} High</span>
                        <span class="result-stat medium">${counts.Medium} Medium</span>
                        <span class="result-stat low">${counts.Low} Low</span>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>URL</th>
                                <th>Method</th>
                                <th>Parameter</th>
                                <th>Payload</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${data.vulnerabilities.map(v => `
                                <tr class="vuln-row severity-${escapeHtml(v.severity).toLowerCase()}">
                                    <td><span class="vuln-type-badge">${escapeHtml(v.type)}</span></td>
                                    <td><span class="severity-badge severity-${escapeHtml(v.severity).toLowerCase()}">${escapeHtml(v.severity)}</span></td>
                                    <td class="url-cell">${escapeHtml(v.url)}</td>
                                    <td><span class="badge badge-${escapeHtml(v.method).toLowerCase()}">${escapeHtml(v.method)}</span></td>
                                    <td><code>${escapeHtml(v.parameter)}</code></td>
                                    <td class="payload-cell"><code>${escapeHtml(v.payload ? v.payload.substring(0, 80) : '-')}</code></td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="icon">🟢</div>
                    <h4>No Vulnerabilities Found</h4>
                    <p>No vulnerabilities have been detected for this scan yet</p>
                </div>
            `;
        }
    } catch (err) {
        console.error('Error loading vulnerabilities:', err);
    }
}

// ============================================================================
// AGGREGATE PAGES — All Subdomains / All Endpoints / All Vulnerabilities
// ============================================================================

let cachedAllSubdomains = [];
let cachedAllEndpoints = [];
let cachedAllVulns = [];
let currentEndpointMethodFilter = 'all';
let currentVulnSeverityFilter = 'all';

// --- ALL SUBDOMAINS ---
async function loadAllSubdomains() {
    try {
        const res = await fetch(`${API_BASE}/all/subdomains`);
        const data = await res.json();
        if (data.success) {
            cachedAllSubdomains = data.subdomains;
            document.getElementById('subdomains-total-badge').textContent = `${data.total} total`;
            renderAllSubdomains(cachedAllSubdomains);
        }
    } catch (err) {
        console.error('Error loading all subdomains:', err);
    }
}

function renderAllSubdomains(subdomains) {
    const table = document.getElementById('all-subdomains-table');
    if (subdomains.length === 0) {
        table.innerHTML = `<tr><td colspan="4" class="empty-state"><div class="icon">🌐</div><h4>No subdomains found</h4><p>Run a scan to discover subdomains</p></td></tr>`;
        return;
    }
    table.innerHTML = subdomains.map(s => `
        <tr style="cursor: pointer;" onclick="viewScan(${s.scan_id})">
            <td style="font-weight: 500;">${escapeHtml(s.subdomain)}</td>
            <td><span style="color: var(--text-muted); font-size: 12px;">${escapeHtml(s.domain)}</span></td>
            <td>${escapeHtml(s.status_code) || '-'}</td>
            <td style="color: var(--text-muted); font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(s.title) || '-'}</td>
        </tr>
    `).join('');
}

function filterAllSubdomains() {
    const q = document.getElementById('subdomains-search').value.toLowerCase();
    const filtered = cachedAllSubdomains.filter(s =>
        s.subdomain.toLowerCase().includes(q) ||
        s.domain.toLowerCase().includes(q) ||
        (s.title && s.title.toLowerCase().includes(q))
    );
    renderAllSubdomains(filtered);
}

// --- ALL ENDPOINTS ---
async function loadAllEndpoints() {
    try {
        const res = await fetch(`${API_BASE}/all/endpoints`);
        const data = await res.json();
        if (data.success) {
            cachedAllEndpoints = data.endpoints;
            const getCount = data.endpoints.filter(e => e.method === 'GET').length;
            const postCount = data.endpoints.filter(e => e.method === 'POST').length;
            document.getElementById('endpoints-get-badge').textContent = `${getCount} GET`;
            document.getElementById('endpoints-post-badge').textContent = `${postCount} POST`;
            document.getElementById('endpoints-total-badge').textContent = `${data.total} total`;
            renderAllEndpoints(cachedAllEndpoints);
        }
    } catch (err) {
        console.error('Error loading all endpoints:', err);
    }
}

function renderAllEndpoints(endpoints) {
    const table = document.getElementById('all-endpoints-table');
    if (endpoints.length === 0) {
        table.innerHTML = `<tr><td colspan="5" class="empty-state"><div class="icon">🔗</div><h4>No endpoints found</h4><p>Run a scan to discover endpoints</p></td></tr>`;
        return;
    }
    table.innerHTML = endpoints.map(e => {
        const params = e.method === 'POST'
            ? (e.body_params ? escapeHtml(Object.keys(e.body_params).join(', ')) : '-')
            : (e.parameters ? escapeHtml(Object.keys(e.parameters).join(', ')) : '-');
        return `
        <tr style="cursor: pointer;" onclick="viewScan(${e.scan_id})">
            <td><span class="badge badge-${e.method.toLowerCase()}">${escapeHtml(e.method)}</span></td>
            <td class="url-cell">${escapeHtml(e.url)}</td>
            <td class="params-cell">${params}</td>
            <td><span style="color: var(--text-muted); font-size: 12px;">${escapeHtml(e.domain)}</span></td>
            <td style="color: var(--text-muted); font-size: 12px;">${escapeHtml(e.source) || '-'}</td>
        </tr>
    `;
    }).join('');
}

function filterAllEndpoints() {
    applyEndpointFilters();
}

function filterAllEndpointsByMethod(method, btn) {
    currentEndpointMethodFilter = method;
    // Update active pill
    btn.closest('.filter-pills').querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    applyEndpointFilters();
}

function applyEndpointFilters() {
    const q = document.getElementById('endpoints-search').value.toLowerCase();
    let filtered = cachedAllEndpoints;

    // Method filter
    if (currentEndpointMethodFilter === 'GET' || currentEndpointMethodFilter === 'POST') {
        filtered = filtered.filter(e => e.method === currentEndpointMethodFilter);
    } else if (currentEndpointMethodFilter === 'params') {
        filtered = filtered.filter(e => e.parameters || e.body_params);
    }

    // Text search
    if (q) {
        filtered = filtered.filter(e =>
            e.url.toLowerCase().includes(q) ||
            e.domain.toLowerCase().includes(q) ||
            (e.source && e.source.toLowerCase().includes(q))
        );
    }
    renderAllEndpoints(filtered);
}

// --- ALL VULNERABILITIES ---
async function loadAllVulnerabilities() {
    try {
        const res = await fetch(`${API_BASE}/all/vulnerabilities`);
        const data = await res.json();
        if (data.success) {
            cachedAllVulns = data.vulnerabilities;
            // Severity badges
            const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
            data.vulnerabilities.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
            document.getElementById('vuln-severity-badges').innerHTML = `
                <span class="result-stat critical">${counts.Critical} Critical</span>
                <span class="result-stat high">${counts.High} High</span>
                <span class="result-stat medium">${counts.Medium} Medium</span>
                <span class="result-stat low">${counts.Low} Low</span>
                <span class="badge badge-completed">${data.total} total</span>
            `;
            renderAllVulns(cachedAllVulns);
        }
    } catch (err) {
        console.error('Error loading all vulnerabilities:', err);
    }
}

function renderAllVulns(vulns) {
    const table = document.getElementById('all-vulns-table');
    if (vulns.length === 0) {
        table.innerHTML = `<tr><td colspan="7" class="empty-state"><div class="icon">🟢</div><h4>No vulnerabilities found</h4><p>Run a vulnerability scan to discover security issues</p></td></tr>`;
        return;
    }
    table.innerHTML = vulns.map(v => `
        <tr class="vuln-row severity-${escapeHtml(v.severity).toLowerCase()}" style="cursor: pointer;" onclick="viewScan(${v.scan_id})">
            <td><span class="vuln-type-badge">${escapeHtml(v.type)}</span></td>
            <td><span class="severity-badge severity-${escapeHtml(v.severity).toLowerCase()}">${escapeHtml(v.severity)}</span></td>
            <td class="url-cell">${escapeHtml(v.url)}</td>
            <td><span class="badge badge-${escapeHtml(v.method).toLowerCase()}">${escapeHtml(v.method)}</span></td>
            <td><code>${escapeHtml(v.parameter)}</code></td>
            <td><span style="color: var(--text-muted); font-size: 12px;">${escapeHtml(v.domain)}</span></td>
            <td class="payload-cell"><code>${escapeHtml(v.payload ? v.payload.substring(0, 80) : '-')}</code></td>
        </tr>
    `).join('');
}

function filterAllVulns() {
    applyVulnFilters();
}

function filterAllVulnsBySeverity(severity, btn) {
    currentVulnSeverityFilter = severity;
    btn.closest('.filter-pills').querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    applyVulnFilters();
}

function applyVulnFilters() {
    const q = document.getElementById('vulns-search').value.toLowerCase();
    let filtered = cachedAllVulns;

    // Severity filter
    if (currentVulnSeverityFilter !== 'all') {
        filtered = filtered.filter(v => v.severity === currentVulnSeverityFilter);
    }

    // Text search
    if (q) {
        filtered = filtered.filter(v =>
            v.url.toLowerCase().includes(q) ||
            v.type.toLowerCase().includes(q) ||
            v.domain.toLowerCase().includes(q) ||
            (v.parameter && v.parameter.toLowerCase().includes(q))
        );
    }
    renderAllVulns(filtered);
}

// ============================================================================
// AI REPORT GENERATION
// ============================================================================

async function generateAIReport() {
    if (!currentScanId) {
        showNotification('No scan selected', 'error');
        return;
    }

    const btn = document.getElementById('ai-report-btn');
    const originalHTML = btn.innerHTML;

    // Set loading state
    btn.classList.add('loading');
    btn.innerHTML = '<span class="btn-report-icon">📄</span><span>Generating...</span><span class="ai-badge">🤖 AI</span>';
    btn.disabled = true;

    try {
        const response = await fetch(`${API_BASE}/scans/${currentScanId}/report`, {
            method: 'POST'
        });

        if (!response.ok) {
            const data = await response.json();
            throw new Error(data.error || 'Failed to generate report');
        }

        // Download the PDF
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;

        // Extract filename from Content-Disposition header or use default
        const disposition = response.headers.get('Content-Disposition');
        let filename = `NileDefender_Report_${currentScanId}.pdf`;
        if (disposition) {
            const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
            if (match) filename = match[1].replace(/['"]/g, '');
        }

        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        showNotification('AI report generated and downloaded!', 'success');
    } catch (error) {
        console.error('AI Report error:', error);
        showNotification(error.message || 'Failed to generate AI report', 'error');
    } finally {
        // Restore button
        btn.classList.remove('loading');
        btn.innerHTML = originalHTML;
        btn.disabled = false;
    }
}

// ============================================================================
// EXPORT SCAN DATA (CSV / JSON)
// ============================================================================

function toggleExportDropdown() {
    const menu = document.getElementById('export-menu');
    menu.classList.toggle('show');
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('export-dropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        document.getElementById('export-menu').classList.remove('show');
    }
});

async function exportScanData(format, dataType) {
    if (!currentScanId) {
        showNotification('No scan selected.', 'error');
        return;
    }

    // Close the dropdown
    document.getElementById('export-menu').classList.remove('show');

    try {
        const domain = document.getElementById('detail-domain').textContent || 'scan';
        const safeDomain = domain.replace(/[^a-zA-Z0-9.-]/g, '_');
        const dateStr = new Date().toISOString().slice(0, 10);

        let exportData = {};

        // Fetch requested data
        if (dataType === 'all' || dataType === 'subdomains') {
            const res = await fetch(`${API_BASE}/scans/${currentScanId}/subdomains`);
            const data = await res.json();
            exportData.subdomains = data.success ? data.subdomains : [];
        }
        if (dataType === 'all' || dataType === 'endpoints') {
            const res = await fetch(`${API_BASE}/scans/${currentScanId}/endpoints`);
            const data = await res.json();
            exportData.endpoints = data.success ? data.endpoints : [];
        }
        if (dataType === 'all' || dataType === 'vulnerabilities') {
            const res = await fetch(`${API_BASE}/scans/${currentScanId}/vulnerabilities`);
            const data = await res.json();
            exportData.vulnerabilities = data.success ? data.vulnerabilities : [];
        }

        const filename = `${safeDomain}_${dataType}_${dateStr}`;

        if (format === 'json') {
            const jsonContent = dataType === 'all'
                ? exportData
                : exportData[dataType];
            downloadFile(
                JSON.stringify(jsonContent, null, 2),
                `${filename}.json`,
                'application/json'
            );
        } else if (format === 'csv') {
            let csvContent = '';
            if (dataType === 'all') {
                // Combine all data types into one CSV with section headers
                if (exportData.subdomains.length > 0) {
                    csvContent += '# SUBDOMAINS\n' + convertToCSV(exportData.subdomains, 'subdomains') + '\n\n';
                }
                if (exportData.endpoints.length > 0) {
                    csvContent += '# ENDPOINTS\n' + convertToCSV(exportData.endpoints, 'endpoints') + '\n\n';
                }
                if (exportData.vulnerabilities.length > 0) {
                    csvContent += '# VULNERABILITIES\n' + convertToCSV(exportData.vulnerabilities, 'vulnerabilities');
                }
            } else {
                csvContent = convertToCSV(exportData[dataType], dataType);
            }
            downloadFile(csvContent, `${filename}.csv`, 'text/csv');
        }

        showNotification(`Exported ${dataType} as ${format.toUpperCase()}`, 'success');

    } catch (err) {
        console.error('Export error:', err);
        showNotification('Export failed: ' + err.message, 'error');
    }
}

function convertToCSV(data, type) {
    if (!data || data.length === 0) return '';

    // Define headers per data type
    const headers = {
        subdomains: ['subdomain', 'status_code', 'title'],
        endpoints: ['method', 'url', 'parameters', 'body_params', 'source'],
        vulnerabilities: ['type', 'severity', 'url', 'method', 'parameter', 'payload', 'evidence']
    };

    const cols = headers[type] || Object.keys(data[0]);

    // Escape CSV value
    const esc = (val) => {
        if (val === null || val === undefined) return '';
        const str = typeof val === 'object' ? JSON.stringify(val) : String(val);
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return '"' + str.replace(/"/g, '""') + '"';
        }
        return str;
    };

    const lines = [cols.join(',')];
    for (const row of data) {
        lines.push(cols.map(col => esc(row[col])).join(','));
    }
    return lines.join('\n');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
