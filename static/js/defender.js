const alertsList = document.getElementById('alerts-list');
const alertsEmpty = document.getElementById('alerts-empty');
const statusBadge = document.getElementById('ids-state');
const ifcSpan = document.getElementById('ids-ifc');
const rangeSpan = document.getElementById('ids-range-val');
const msgSpan = document.getElementById('ids-message');
const statPackets = document.getElementById('stat-packets');
const statAlerts = document.getElementById('stat-alerts');
const statArp = document.getElementById('stat-arp');
const statSyn = document.getElementById('stat-syn');
const statBlocks = document.getElementById('stat-blocks');
const startedSpan = document.getElementById('ids-started');
const nodesBody = document.getElementById('nodes-body');
const nodesEmpty = document.getElementById('nodes-empty');
const overviewMsg = document.getElementById('overview-message');

function setMessage(text, isError = false) {
    if (!msgSpan) return;
    msgSpan.textContent = text;
    msgSpan.style.color = isError ? '#ff6b6b' : '#9a9a9a';
    if (overviewMsg) {
        overviewMsg.textContent = text;
    }
}

function severityClass(sev) {
    if (!sev) return 'gray';
    const s = sev.toLowerCase();
    if (s === 'high') return 'red';
    if (s === 'medium') return 'yellow';
    return 'green';
}

function statusBadgeClass(status) {
    if (status === 'safe') return 'green';
    if (status === 'danger') return 'red';
    return 'yellow';
}

async function fetchOverview() {
    try {
        const res = await fetch('/api/ids/overview');
        if (!res.ok) throw new Error('overview request failed');
        const data = await res.json();
        const status = data.status || {};
        const stats = status.stats || {};

        const running = !!status.running;
        statusBadge.textContent = running ? 'running' : 'stopped';
        statusBadge.className = `badge ${running ? 'green' : 'red'}`;
        ifcSpan.textContent = status.interface || 'auto';
        rangeSpan.textContent = status.network_range || data.network_range || '-';

        statPackets.textContent = stats.packets_seen || 0;
        statAlerts.textContent = stats.alerts || 0;
        statArp.textContent = stats.arp_scans || 0;
        statSyn.textContent = stats.syn_events || 0;
        statBlocks.textContent = (data.stats && data.stats.blocks_requested) || 0;
        startedSpan.textContent = stats.started_at || '-';

        renderNodes(data.nodes || []);
        renderAlerts(data.alerts || []);
    } catch (err) {
        setMessage(`Status error: ${err.message}`, true);
    }
}

function renderNodes(nodes) {
    if (!nodesBody) return;
    nodesBody.innerHTML = '';
    if (!nodes || nodes.length === 0) {
        nodesEmpty.style.display = 'block';
        return;
    }
    nodesEmpty.style.display = 'none';

    nodes.forEach((node) => {
        const tr = document.createElement('tr');
        const status = node.status || 'unknown';
        const badge = `<span class="badge ${statusBadgeClass(status)}">${status}</span>`;
        const hostname = node.hostname || 'Unknown host';
        const ip = node.ip || '-';
        const mac = node.mac || '-';
        const openPorts = node.open_ports && node.open_ports.length ? node.open_ports.join(', ') : '—';
        const services = (node.services || []).map((s) => `${s.port}/${s.service}`).join(', ') || '—';

        tr.innerHTML = `
            <td>${badge}</td>
            <td><strong>${hostname}</strong></td>
            <td>${ip}<br /><span class="muted">${mac}</span></td>
            <td>${openPorts}</td>
            <td>${services}</td>
            <td><button class="btn btn-danger" onclick="blockIp('${ip}', '${mac}')">Block</button></td>
        `;
        nodesBody.appendChild(tr);
    });
}

function renderAlerts(alerts) {
    if (!alertsList) return;
    alertsList.innerHTML = '';
    if (!alerts || alerts.length === 0) {
        alertsEmpty.style.display = 'block';
        return;
    }
    alertsEmpty.style.display = 'none';

    alerts.slice().reverse().forEach((alert) => {
        const card = document.createElement('div');
        card.className = 'alert-card';

        const header = document.createElement('div');
        header.style.display = 'flex';
        header.style.justifyContent = 'space-between';
        header.style.alignItems = 'center';

        const title = document.createElement('div');
        title.innerHTML = `<strong>${alert.type || 'ALERT'}</strong> <span class="pill">${alert.id}</span>`;
        const badge = document.createElement('span');
        badge.className = `badge ${severityClass(alert.severity)}`;
        badge.textContent = alert.severity || 'info';
        header.appendChild(title);
        header.appendChild(badge);

        const summary = document.createElement('p');
        summary.textContent = alert.summary || '';
        const meta = document.createElement('p');
        meta.className = 'muted';
        meta.textContent = alert.timestamp || '';

        const details = document.createElement('pre');
        details.className = 'muted';
        details.style.whiteSpace = 'pre-wrap';
        details.style.fontSize = '0.9rem';
        details.textContent = JSON.stringify(alert.details || {}, null, 2);

        const btns = document.createElement('div');
        btns.className = 'btn-row';
        const ack = document.createElement('button');
        ack.className = 'btn btn-success';
        ack.textContent = alert.acknowledged ? 'Acknowledged' : 'Acknowledge';
        ack.disabled = !!alert.acknowledged;
        ack.onclick = () => ackAlert(alert.id);

        const block = document.createElement('button');
        block.className = 'btn btn-danger';
        block.textContent = 'Block';
        block.onclick = () => blockAlertTarget(alert);

        btns.appendChild(ack);
        btns.appendChild(block);

        card.appendChild(header);
        card.appendChild(summary);
        card.appendChild(meta);
        card.appendChild(details);
        card.appendChild(btns);

        alertsList.appendChild(card);
    });
}

async function startIds() {
    try {
        const payload = {
            interface: document.getElementById('ids-interface').value || null,
            network_range: document.getElementById('ids-range').value || null,
            arp_interval: Number(document.getElementById('ids-arp').value || 20),
            syn_threshold: Number(document.getElementById('ids-syn-th').value || 150),
            syn_window_sec: Number(document.getElementById('ids-syn-win').value || 10),
            syn_unique_sources: Number(document.getElementById('ids-syn-unique').value || 15),
        };

        const res = await fetch('/api/ids/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'start failed');
        setMessage(data.message || 'IDS started');
        fetchOverview();
    } catch (err) {
        setMessage(`Start error: ${err.message}`, true);
    }
}

async function stopIds() {
    try {
        const res = await fetch('/api/ids/stop', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'stop failed');
        setMessage(data.message || 'IDS stopped');
        fetchOverview();
    } catch (err) {
        setMessage(`Stop error: ${err.message}`, true);
    }
}

async function ackAlert(id) {
    try {
        const res = await fetch(`/api/ids/alerts/${id}/ack`, { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'ack failed');
        setMessage('Alert acknowledged');
        fetchOverview();
    } catch (err) {
        setMessage(`Ack error: ${err.message}`, true);
    }
}

async function blockAlertTarget(alert) {
    const details = alert.details || {};
    await blockIp(details.dst_ip || details.ip || null, details.mac || null, alert.id);
}

async function blockIp(ip, mac, alertId = null) {
    if (!ip) return;
    try {
        const res = await fetch('/api/ids/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: alertId,
                target_ip: ip,
                target_mac: mac,
                reason: 'defender_action',
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'block failed');
        setMessage('Block recorded');
    } catch (err) {
        setMessage(`Block error: ${err.message}`, true);
    }
}

async function refreshInventory() {
    try {
        setMessage('Refreshing network...');
        const res = await fetch('/api/ids/discover', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'discover failed');
        renderNodes(data.nodes || []);
        setMessage('Inventory refreshed');
    } catch (err) {
        setMessage(`Discover error: ${err.message}`, true);
    }
}

function wireButtons() {
    const startBtn = document.getElementById('start-ids-btn');
    const stopBtn = document.getElementById('stop-ids-btn');
    const refreshBtn = document.getElementById('refresh-inventory');
    if (startBtn) startBtn.onclick = startIds;
    if (stopBtn) stopBtn.onclick = stopIds;
    if (refreshBtn) refreshBtn.onclick = refreshInventory;
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        wireButtons();
        fetchOverview();
        setInterval(fetchOverview, 4000);
    });
} else {
    wireButtons();
    fetchOverview();
    setInterval(fetchOverview, 4000);
}
