"""
IDS Routes - start/stop/status + alert actions
Accessible to DEFENDER role.
"""

from flask import Blueprint, jsonify, request, session
from functools import wraps
from datetime import datetime
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import models
from modules.ids_monitor import IDSMonitor
from modules.network_scanner import NetworkScanner
from models import (
    register_ids_monitor,
    record_ids_alert,
    list_ids_alerts,
    ack_ids_alert,
    request_block,
    ids_stats,
    ids_alerts,
)
from utils.logger import get_logger
from utils.network_utils import get_default_network_range

ids_bp = Blueprint('ids', __name__)
logger = get_logger("IDSRoutes")

_discovery_cache = {
    'ts': 0.0,
    'nodes': [],
    'range': None,
}
_DISCOVERY_TTL = 30


# ============================================================================
# MIDDLEWARE: Check Defender Role
# ============================================================================

def require_defender(f):
    """Decorator to require defender role"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_role = session.get('user_role')
        user_id = session.get('user_id')
        logger.info(f"Auth check: user_id={user_id}, role={user_role}")
        if user_role != 'DEFENDER':
            logger.warning(f"Access denied: expected DEFENDER, got {user_role}")
            return jsonify({'error': 'Access denied', 'required_role': 'DEFENDER', 'current_role': user_role}), 403
        return f(*args, **kwargs)

    return decorated_function


# ============================================================================
# IDS CONTROL ENDPOINTS
# ============================================================================


@ids_bp.route('/ids/start', methods=['POST'])
@require_defender
def start_ids():
    try:
        data = request.get_json(silent=True) or {}
        interface = data.get('interface')
        network_range = data.get('network_range')
        arp_interval = int(data.get('arp_interval', 20))
        syn_threshold = int(data.get('syn_threshold', 500))  # Increased: real flood needs 500+ SYNs
        syn_window_sec = int(data.get('syn_window_sec', 10))
        syn_unique_sources = int(data.get('syn_unique_sources', 20))  # Increased: real attack from 20+ sources

        monitor = models.ids_monitor
        if monitor and monitor.running.is_set():
            return jsonify({'status': 'running', 'message': 'IDS already running'}), 200

        monitor = IDSMonitor(
            interface=interface,
            network_range=network_range,
            arp_interval=arp_interval,
            syn_threshold=syn_threshold,
            syn_window_sec=syn_window_sec,
            syn_unique_sources=syn_unique_sources,
            alert_sink=record_ids_alert,
        )
        register_ids_monitor(monitor)
        monitor.start()

        return jsonify({
            'status': 'started',
            'config': monitor.get_status(),
            'message': 'IDS monitor started'
        }), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to start IDS: {exc}")
        return jsonify({'error': str(exc)}), 500


@ids_bp.route('/ids/stop', methods=['POST'])
@require_defender
def stop_ids():
    try:
        monitor = models.ids_monitor
        if not monitor:
            return jsonify({'status': 'stopped', 'message': 'IDS not initialized'}), 200
        monitor.stop()
        return jsonify({'status': 'stopped', 'message': 'IDS monitor stopped'}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to stop IDS: {exc}")
        return jsonify({'error': str(exc)}), 500


@ids_bp.route('/ids/status', methods=['GET'])
@require_defender
def status_ids():
    try:
        monitor = models.ids_monitor
        status_payload = monitor.get_status() if monitor else {
            'running': False,
            'interface': None,
            'network_range': None,
            'config': {},
            'stats': {},
            'alerts': [],
        }
        return jsonify({
            'status': status_payload,
            'alerts': list_ids_alerts(limit=50),
            'stats': ids_stats,
        }), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to fetch IDS status: {exc}")
        return jsonify({'error': str(exc)}), 500


@ids_bp.route('/ids/overview', methods=['GET'])
@require_defender
def ids_overview():
    """Aggregate IDS status, alerts, stats, and a live node inventory."""
    try:
        logger.info("Fetching IDS overview (fast scan)...")
        nodes, network_range = _get_or_discover_nodes()
        monitor = models.ids_monitor
        status_payload = monitor.get_status() if monitor else {
            'running': False,
            'interface': None,
            'network_range': network_range,
            'config': {},
            'stats': {},
            'alerts': [],
        }
        
        logger.info(f"Overview: {len(nodes)} nodes, {len(list_ids_alerts())} alerts")
        return jsonify({
            'status': status_payload,
            'alerts': list_ids_alerts(limit=100),
            'stats': ids_stats,
            'nodes': nodes,
            'network_range': network_range,
            'last_discovery': _discovery_cache['ts'],
        }), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to fetch overview: {exc}", exc_info=True)
        return jsonify({'error': str(exc)}), 500


@ids_bp.route('/ids/discover', methods=['POST'])
@require_defender
def ids_discover_now():
    """Force a fresh node discovery and return it."""
    try:
        _discovery_cache['ts'] = 0
        nodes, network_range = _get_or_discover_nodes(force=True)
        return jsonify({'nodes': nodes, 'network_range': network_range}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to discover nodes: {exc}")
        return jsonify({'error': str(exc)}), 500


# ============================================================================
# ALERT ACTIONS
# ============================================================================


@ids_bp.route('/ids/alerts/<alert_id>/ack', methods=['POST'])
@require_defender
def ack_alert_route(alert_id):
    try:
        if ack_ids_alert(alert_id):
            return jsonify({'status': 'acknowledged'}), 200
        return jsonify({'error': 'Alert not found'}), 404
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to acknowledge alert: {exc}")
        return jsonify({'error': str(exc)}), 500


@ids_bp.route('/ids/block', methods=['POST'])
@require_defender
def block_entity():
    """Block an IP using system firewall."""
    try:
        data = request.get_json(silent=True) or {}
        alert_id = data.get('alert_id')
        target_ip = data.get('target_ip')
        target_mac = data.get('target_mac')
        reason = data.get('reason') or 'manual'

        if not target_ip:
            return jsonify({'error': 'target_ip required'}), 400

        # Record the block request
        entity = {
            'alert_id': alert_id,
            'target_ip': target_ip,
            'target_mac': target_mac,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'blocked': False,
        }
        
        # Actually block the IP using firewall
        blocker = models.firewall_blocker
        if blocker:
            success = blocker.block_ip(target_ip, reason)
            entity['blocked'] = success
            if success:
                models.ids_stats['blocks_executed'] = models.ids_stats.get('blocks_executed', 0) + 1
                models.blocked_ips.add(target_ip)  # Track blocked IP
                logger.info(f"✅ Blocked {target_ip} via firewall (reason: {reason})")
            else:
                logger.warning(f"⚠️ Failed to block {target_ip} via firewall")
        else:
            logger.warning("⚠️ Firewall blocker not initialized")
        
        request_block(entity)
        return jsonify({'status': 'blocked' if entity['blocked'] else 'recorded', 'action': entity}), 200
    except Exception as exc:  # noqa: BLE001
        logger.error(f"Failed to block: {exc}")
        return jsonify({'error': str(exc)}), 500


# ============================================================================
# NODE DISCOVERY HELPERS
# ============================================================================


def _node_status(node, alerts):
    ip = node.get('ip') if isinstance(node, dict) else None
    if not ip:
        return 'danger'

    # Whitelist: gateway and trusted servers are always safe
    whitelist = {'192.168.111.1', '192.168.111.2', '192.168.111.254', '192.168.111.12'}
    if ip in whitelist:
        return 'safe'

    # Mark as danger if any alert references this IP
    for alert in alerts:
        details = alert.get('details', {}) if isinstance(alert, dict) else {}
        if ip in [details.get('dst_ip'), details.get('ip'), details.get('src_ip')]:
            return 'danger'

    hostname = node.get('hostname') if isinstance(node, dict) else None
    if not hostname:
        return 'danger'

    return 'safe'


def _annotate_nodes(hosts, alerts):
    nodes = []
    for host in hosts:
        data = host.to_dict() if hasattr(host, 'to_dict') else dict(host)
        data['status'] = _node_status(data, alerts)
        nodes.append(data)
    return nodes


def _get_or_discover_nodes(force: bool = False):
    now = time.time()
    # Cache discovery results for 10 seconds to keep UI responsive
    if not force and (now - _discovery_cache['ts']) < 10 and _discovery_cache['nodes']:
        return _discovery_cache['nodes'], _discovery_cache['range']

    monitor = models.ids_monitor
    iface = monitor.interface if monitor else None
    net_range = monitor.network_range if monitor else get_default_network_range(iface) or '192.168.1.0/24'

    scanner = NetworkScanner(interface=iface)
    hosts = scanner.identify_active_machines(net_range, False)
    nodes = _annotate_nodes(hosts, ids_alerts)

    _discovery_cache['ts'] = now
    _discovery_cache['nodes'] = nodes
    _discovery_cache['range'] = net_range
    return nodes, net_range
