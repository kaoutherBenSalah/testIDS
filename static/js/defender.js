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
const startedSpan = document.getElementById('ids-started');

function setMessage(text, isError = false) {
    if (!msgSpan) return;
    msgSpan.textContent = text;
    msgSpan.style.color = isError ? '#ff6b6b' : '#9a9a9a';
}

function severityClass(sev) {
    if (!sev) return 'gray';
    const s = sev.toLowerCase();
    if (s === 'high') return 'red';
    if (s === 'medium') return 'yellow';
    return 'green';
}

async function fetchStatus() {
    try {
        const res = await fetch('/api/ids/status');
        if (!res.ok) throw new Error('status request failed');
        const data = await res.json();
        const status = data.status || {};
        const stats = status.stats || {};

        const running = !!status.running;
        statusBadge.textContent = running ? 'running' : 'stopped';
        statusBadge.className = `badge ${running ? 'green' : 'red'}`;
        ifcSpan.textContent = status.interface || 'auto';
        rangeSpan.textContent = status.network_range || '-';

        statPackets.textContent = stats.packets_seen || 0;
        statAlerts.textContent = stats.alerts || 0;
        statArp.textContent = stats.arp_scans || 0;
        statSyn.textContent = stats.syn_events || 0;
        startedSpan.textContent = stats.started_at || '-';

        renderAlerts(data.alerts || []);
    } catch (err) {
        setMessage(`Status error: ${err.message}`, true);
    }
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

        const header = document.createElement('header');
        const title = document.createElement('div');
        title.innerHTML = `<strong>${alert.type || 'ALERT'}</strong> <span class="pill gray small">${alert.id}</span>`;
        const badge = document.createElement('span');
        badge.className = `badge ${severityClass(alert.severity)}`;
        badge.textContent = alert.severity || 'info';
        header.appendChild(title);
        header.appendChild(badge);

        const summary = document.createElement('p');
        summary.textContent = alert.summary || '';
        const meta = document.createElement('p');
        meta.className = 'muted';
        meta.textContent = `${alert.timestamp || ''}`;

        const details = document.createElement('pre');
        details.className = 'muted';
        details.style.whiteSpace = 'pre-wrap';
        details.style.fontSize = '0.9rem';
        details.textContent = JSON.stringify(alert.details || {}, null, 2);

        const btns = document.createElement('div');
        btns.className = 'btn-inline';
        const ack = document.createElement('button');
        ack.className = 'btn btn-success';
        ack.textContent = alert.acknowledged ? 'Acknowledged' : 'Acknowledge';
        ack.disabled = !!alert.acknowledged;
        ack.onclick = () => ackAlert(alert.id);

        const block = document.createElement('button');
        block.className = 'btn btn-danger';
        block.textContent = 'Block / Stop';
        block.onclick = () => blockTarget(alert);

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
        fetchStatus();
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
        fetchStatus();
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
        fetchStatus();
    } catch (err) {
        setMessage(`Ack error: ${err.message}`, true);
    }
}

async function blockTarget(alert) {
    try {
        const details = alert.details || {};
        const res = await fetch('/api/ids/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: alert.id,
                target_ip: details.dst_ip || details.ip || null,
                target_mac: details.mac || null,
                reason: 'defender_action',
            }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'block failed');
        setMessage('Block/stop recorded');
    } catch (err) {
        setMessage(`Block error: ${err.message}`, true);
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fetchStatus);
} else {
    fetchStatus();
}
setInterval(fetchStatus, 5000);
