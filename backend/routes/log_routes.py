# ============================================================
# backend/routes/log_routes.py
# Network Log Routes: /logs
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import logging

log_bp = Blueprint('logs', __name__)
logger = logging.getLogger(__name__)


@log_bp.route('/logs', methods=['GET'])
@jwt_required()
def get_logs():
    """
    GET /api/logs
    Query: ?page=1&limit=50&source_ip=&action=DENY&protocol=TCP
    """
    from models import NetworkLog

    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 50)), 200)
    source_ip = request.args.get('source_ip')
    action = request.args.get('action')
    protocol = request.args.get('protocol')

    query = NetworkLog.query

    if source_ip:
        query = query.filter(NetworkLog.source_ip.like(f'%{source_ip}%'))
    if action:
        query = query.filter_by(action=action.upper())
    if protocol:
        query = query.filter_by(protocol=protocol.upper())

    pagination = query.order_by(NetworkLog.timestamp.desc()).paginate(
        page=page, per_page=limit, error_out=False
    )

    return jsonify({
        'logs': [log.to_dict() for log in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page,
        'per_page': limit
    }), 200


@log_bp.route('/logs/recent', methods=['GET'])
@jwt_required()
def get_recent_logs():
    """GET /api/logs/recent — last 20 logs for live feed."""
    from models import NetworkLog

    logs = NetworkLog.query.order_by(NetworkLog.timestamp.desc()).limit(20).all()
    return jsonify({'logs': [l.to_dict() for l in logs]}), 200


@log_bp.route('/logs/stats', methods=['GET'])
@jwt_required()
def get_log_stats():
    """GET /api/logs/stats — summary stats for dashboard."""
    from models import NetworkLog, AttackPrediction, Alert, BlockedIP
    from app import db
    from sqlalchemy import func

    total_logs = NetworkLog.query.count()
    total_attacks = AttackPrediction.query.filter(
        AttackPrediction.attack_type != 'Normal'
    ).count()
    active_alerts = Alert.query.filter_by(is_resolved=False).count()
    blocked_ips = BlockedIP.query.filter_by(is_active=True).count()
    critical_count = AttackPrediction.query.filter_by(risk_level='CRITICAL').count()

    # Attacks in last 24 hours
    from datetime import datetime, timedelta
    cutoff = datetime.utcnow() - timedelta(hours=24)
    recent_attacks = AttackPrediction.query.filter(
        AttackPrediction.timestamp >= cutoff,
        AttackPrediction.attack_type != 'Normal'
    ).count()

    # Attack type breakdown
    type_breakdown = db.session.query(
        AttackPrediction.attack_type,
        func.count(AttackPrediction.id).label('count')
    ).group_by(AttackPrediction.attack_type).all()

    # Risk level breakdown
    risk_breakdown = db.session.query(
        AttackPrediction.risk_level,
        func.count(AttackPrediction.id).label('count')
    ).group_by(AttackPrediction.risk_level).all()

    return jsonify({
        'total_logs': total_logs,
        'total_attacks': total_attacks,
        'active_alerts': active_alerts,
        'blocked_ips': blocked_ips,
        'critical_count': critical_count,
        'recent_attacks_24h': recent_attacks,
        'attack_type_breakdown': [
            {'type': t, 'count': c} for t, c in type_breakdown
        ],
        'risk_level_breakdown': [
            {'level': l, 'count': c} for l, c in risk_breakdown
        ]
    }), 200
