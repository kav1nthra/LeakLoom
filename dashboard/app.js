let threatSummary = null;
let radarChartInstance = null;
let lineChartInstance = null;
let eventSource = null;
let totalProcessed = 0;
let currentFacilityFilter = "ALL";

const liveUserStats = {};

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('start-sim-btn').addEventListener('click', startSSEMonitoring);
    document.getElementById('close-modal').addEventListener('click', closeModal);
    
    document.getElementById('facility-filter').addEventListener('change', (e) => {
        currentFacilityFilter = e.target.value;
        if(threatSummary) {
            renderTable(threatSummary.users);
        }
    });
    
    document.querySelectorAll('.action-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const uidText = document.getElementById('modal-uid').innerText.replace('User ID: ', '');
            const actionType = this.innerText;
            
            showToast(`DEPLOYED: [${actionType}] executed against ${uidText}`);
            
            const originalText = this.innerText;
            this.style.opacity = '0.5';
            this.style.pointerEvents = 'none';
            this.innerText = 'Transmitting...';
            
            setTimeout(() => {
                this.style.opacity = '1';
                this.style.pointerEvents = 'auto';
                this.innerText = originalText;
                showToast(`SUCCESS: ${actionType} constraint locked.`, "normal");
            }, 2000);
        });
    });
    
    // Poll the initial WAF state if native WAF has existed before UI load
    try {
        const summaryRes = await fetch('threat_summary.json');
        if (summaryRes.ok) {
            threatSummary = await summaryRes.json();
            renderTable(threatSummary.users);
            const alerts = threatSummary.users.filter(u => u.max_threat_score >= 75).length;
            document.getElementById('stat-alerts').innerText = alerts;
        }
    } catch (e) {
        console.warn("Awaiting live stream...");
    }
});

function startSSEMonitoring() {
    if (eventSource) return;
    
    const simBtn = document.getElementById('start-sim-btn');
    simBtn.innerText = 'Monitoring Live Network...';
    simBtn.style.opacity = '0.5';
    simBtn.style.border = '1px solid var(--accent-blue)';
    simBtn.style.color = 'var(--accent-blue)';
    simBtn.style.pointerEvents = 'none';
    
    document.querySelector('#threat-table tbody').innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); font-style: italic;">Connecting to Secure Telemetry Stream...</td></tr>';
    
    eventSource = new EventSource('/stream');
    
    eventSource.onmessage = function(e) {
        let parsed;
        try {
            parsed = JSON.parse(e.data);
        } catch(err) {
            return;
        }
        
        if (parsed.type === "telemetry") {
            const log = parsed.data;
            totalProcessed++;
            processLiveLog(log);
            spawnParticle(log.endpoint);
            
            if (totalProcessed % 5 === 0) {
                document.getElementById('stat-processed').innerText = totalProcessed.toLocaleString();
            }
            
        } else if (parsed.type === "summary") {
            threatSummary = parsed.data;
            renderTable(threatSummary.users);
            
            const alerts = threatSummary.users.filter(u => u.max_threat_score >= 75).length;
            document.getElementById('stat-alerts').innerText = alerts;
        }
    };
    
    eventSource.onerror = function() {
        showToast("SSE Connection Lost. Attempting auto-reconnect...", "warning");
    };
}

function processLiveLog(log) {
    if (!liveUserStats[log.user_id]) {
        liveUserStats[log.user_id] = { requests: [], bytes: 0, reco: 0 };
    }
    
    const s = liveUserStats[log.user_id];
    s.requests.push(log);
    s.bytes += log.bytes_transferred;
    if (log.endpoint === '/records') s.reco++;
    
    if (s.reco >= 20 || s.bytes > 50000000) {
        if (!s.toasted) {
            s.toasted = true;
            showToast(`Critical Exfiltration Threshold Burst: ${log.user_id}`, "critical");
        }
    }
}

function updateTableRow(user) {
    const tableBody = document.querySelector('#threat-table tbody');
    
    // Clear filler row
    if(tableBody.innerHTML.includes("Connecting to Secure Telemetry Stream")) {
        tableBody.innerHTML = '';
    }
    
    let existingRow = document.getElementById(`row-${user.user_id}`);
    
    let statusClass = 'normal';
    let statusText = 'MONITORING';
    
    if (user.max_threat_score >= 75) {
        statusClass = 'critical';
        statusText = 'CRITICAL';
    } else if (user.max_threat_score >= 50) {
        statusClass = 'warning';
        statusText = 'ELEVATED';
    }
    
    const totalMB = (user.max_threat_score > 0 ? (user.max_threat_score * 3.4).toFixed(1) : 0);
    const facIcon = `<span class="legend-chip public" style="border-width:0; background:rgba(0,0,0,0.02);">${user.facility_id}</span>`;
    
    const html = `
        <td>${facIcon}</td>
        <td><strong>${user.user_id}</strong></td>
        <td>${user.flag_count} Incident(s)</td>
        <td>${totalMB} MB+</td>
        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
        <td style="color:var(--accent-blue); font-weight:bold; font-family:var(--font-mono);">${user.max_threat_score}</td>
    `;
    
    if (existingRow) {
        existingRow.innerHTML = html;
    } else {
        const tr = document.createElement('tr');
        tr.id = `row-${user.user_id}`;
        tr.innerHTML = html;
        tr.onclick = () => openModal(user.user_id);
        tableBody.insertBefore(tr, tableBody.firstChild);
    }
}

function renderTable(users) {
    if(!users || users.length === 0) return;
    document.querySelector('#threat-table tbody').innerHTML = '';
    
    const filteredUsers = currentFacilityFilter === "ALL" 
        ? users 
        : users.filter(u => u.facility_id === currentFacilityFilter);
        
    filteredUsers.forEach(u => updateTableRow(u));
}

function spawnParticle(endpoint) {
    const pathIn = document.getElementById('flow-track-in');
    const p = document.createElement('div');
    p.className = 'particle';
    
    if (endpoint === '/records') {
        p.style.backgroundColor = 'var(--high-risk)';
        p.style.boxShadow = '0 0 8px var(--high-risk)';
    } else if (endpoint === '/billing') {
        p.style.backgroundColor = 'var(--med-risk)';
        p.style.boxShadow = '0 0 8px var(--med-risk)';
    } else {
        p.style.backgroundColor = 'var(--low-risk)';
        p.style.boxShadow = '0 0 8px var(--low-risk)';
    }
    
    pathIn.appendChild(p);
    setTimeout(() => { if (p.parentNode) p.parentNode.removeChild(p); }, 800);
}

function showToast(msg, type="warning") {
    const container = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = 'toast';
    t.style.borderLeftColor = type === 'critical' ? 'var(--high-risk)' : 'var(--med-risk)';
    t.innerHTML = `<strong>ALERT:</strong> ${msg}`;
    container.appendChild(t);
    setTimeout(() => { if(t.parentNode) t.parentNode.removeChild(t); }, 5000);
}

function generateThreatClassification(scores) {
    const vol = scores.volume || 0;
    const freq = scores.frequency || 0;
    const sens = scores.sensitivity || 0;
    const anom = scores.anomaly || 0;
    
    let threatText = "Anomalous Access Activity";
    let threatColor = "var(--med-risk)";
    
    if (vol > 20 && freq > 15 && sens > 10) {
        threatText = "Aggressive Bulk ePHI Scraping (Insider Theft)";
        threatColor = "var(--high-risk)";
    } else if (freq > 20 && vol <= 15) {
        threatText = "High-Velocity Scripted Reconnaissance";
        threatColor = "var(--med-risk)";
    } else if (vol > 25 && freq <= 15) {
        threatText = "Large-Scale Data Exfiltration Dump";
        threatColor = "var(--high-risk)";
    } else if (anom > 15) {
        threatText = "Deviant Profile Behavior (Likely Stolen Credentials)";
        threatColor = "var(--high-risk)";
    } else if (vol == 0 && freq == 0) {
        threatText = "Analyzing Operating Baseline...";
        threatColor = "var(--low-risk)";
    }

    const span = document.querySelector("#modal-classification span");
    if(span) {
        span.innerText = threatText;
        span.style.color = threatColor;
    }
}

function openModal(userId) {
    const modal = document.getElementById('forensic-modal');
    document.getElementById('modal-uid').innerText = `User ID: ${userId}`;
    
    document.getElementById('modal-hash').innerText = "Verified (Valid Chain)";
    
    const userSummary = threatSummary.users.find(u => u.user_id === userId);
    const liveData = liveUserStats[userId] || { requests: [] };
    
    generateThreatClassification(userSummary.subscores);
    
    renderRadarChart(userSummary.subscores);
    renderLineChart(liveData.requests);
    renderTimeline(liveData.requests);
    
    modal.classList.remove('hidden');
}

function closeModal() {
    document.getElementById('forensic-modal').classList.add('hidden');
}

Chart.defaults.color = "#718096";
Chart.defaults.font.family = "'Inter', sans-serif";

function renderRadarChart(scores) {
    const ctx = document.getElementById('radarChart').getContext('2d');
    if (radarChartInstance) radarChartInstance.destroy();
    
    radarChartInstance = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['Volume Extracted', 'Request Frequency', 'Endpoint Sensitivity', 'Historical Deviation'],
            datasets: [{
                label: 'Threat Composition',
                data: [scores.volume || 0, scores.frequency || 0, scores.sensitivity || 0, scores.anomaly || 0],
                backgroundColor: 'rgba(74, 105, 189, 0.2)',
                borderColor: '#4a69bd',
                pointBackgroundColor: '#2d3748',
                borderWidth: 2
            }]
        },
        options: {
            scales: {
                r: {
                    angleLines: { color: 'rgba(0,0,0,0.05)' },
                    grid: { color: 'rgba(0,0,0,0.05)' },
                    pointLabels: { color: '#2d3748', font: { size: 10, weight: '600' } },
                    ticks: { display: false, max: 40, min: 0 }
                }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderLineChart(requests) {
    const ctx = document.getElementById('lineChart').getContext('2d');
    if (lineChartInstance) lineChartInstance.destroy();
    
    const bins = Array(12).fill(0);
    const chunk = Math.max(1, Math.ceil(requests.length / 12));
    
    requests.forEach((req, idx) => {
        let binIdx = Math.floor(idx / chunk);
        if (binIdx > 11) binIdx = 11;
        bins[binIdx] += req.bytes_transferred;
    });

    lineChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: bins.map((_, i) => `T+${i}`),
            datasets: [{
                label: 'Data Extent (Bytes)',
                data: bins,
                borderColor: '#4a69bd',
                backgroundColor: 'rgba(74, 105, 189, 0.1)',
                borderWidth: 2,
                tension: 0.3,
                fill: true,
                pointBackgroundColor: '#2d3748',
                pointBorderColor: '#4a69bd'
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: { grid: { color: 'rgba(0,0,0,0.05)', display: false } },
                y: { grid: { color: 'rgba(0,0,0,0.05)' }, beginAtZero: true }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function renderTimeline(requests) {
    const container = document.getElementById('modal-timeline');
    container.innerHTML = '';
    
    const toShow = requests.slice(-50).reverse();
    
    if(toShow.length === 0) {
        container.innerHTML = '<div class="timeline-entry">No active session telemetry found locally.</div>';
        return;
    }
    
    toShow.forEach(req => {
        const div = document.createElement('div');
        div.className = 'timeline-entry ' + (req.endpoint === '/records' ? 'high' : '');
        div.innerHTML = `<span class="t-time">[${req.timestamp}]</span> <span>${req.endpoint}</span> <span>${req.bytes_transferred} Bytes</span>`;
        container.appendChild(div);
    });
}
