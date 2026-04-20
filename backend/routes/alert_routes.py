# ============================================================
# backend/routes/alert_routes.py
# Alert Routes: /alerts
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
import logging

alert_bp = Blueprint('alerts', __name__)
logger = logging.getLogger(__name__)


@alert_bp.route('/alerts', methods=['GET'])
@jwt_required()
def get_alerts():
    """
    GET /api/alerts
    Query: ?severity=CRITICAL&resolved=false&page=1&limit=20
    """
    from models import Alert

    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 100)
    severity = request.args.get('severity')
    resolved = request.args.get('resolved', 'false').lower()

    query = Alert.query

    if severity:
        query = query.filter_by(severity=severity.upper())

    if resolved == 'false':
        query = query.filter_by(is_resolved=False)
    elif resolved == 'true':
        query = query.filter_by(is_resolved=True)

    pagination = query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=limit, error_out=False
    )

    return jsonify({
        'alerts': [a.to_dict() for a in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200


@alert_bp.route('/alerts/recent', methods=['GET'])
@jwt_required()
def get_recent_alerts():
    """GET /api/alerts/recent — last 10 unresolved alerts."""
    from models import Alert

    alerts = Alert.query.filter_by(is_resolved=False)\
        .order_by(Alert.timestamp.desc()).limit(10).all()

    return jsonify({'alerts': [a.to_dict() for a in alerts]}), 200


@alert_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@jwt_required()
def resolve_alert(alert_id):
    """POST /api/alerts/{id}/resolve — mark alert as resolved."""
    from app import db
    from models import Alert

    user_id = int(get_jwt_identity())
    alert = Alert.query.get_or_404(alert_id)

    if alert.is_resolved:
        return jsonify({'message': 'Alert already resolved', 'alert': alert.to_dict()}), 200

    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolved_by = user_id
    db.session.commit()

    return jsonify({
        'message': f'Alert #{alert_id} resolved',
        'alert': alert.to_dict()
    }), 200


@alert_bp.route('/alerts/resolve-all', methods=['POST'])
@jwt_required()
def resolve_all_alerts():
    """POST /api/alerts/resolve-all — resolve all unresolved alerts."""
    from app import db
    from models import Alert

    user_id = int(get_jwt_identity())
    count = Alert.query.filter_by(is_resolved=False).update({
        'is_resolved': True,
        'resolved_at': datetime.utcnow(),
        'resolved_by': user_id
    })
    db.session.commit()

    return jsonify({'message': f'{count} alerts resolved'}), 200


@alert_bp.route('/alerts/summary', methods=['GET'])
@jwt_required()
def alert_summary():
    """GET /api/alerts/summary — counts by severity."""
    from models import Alert
    from app import db
    from sqlalchemy import func

    summary = db.session.query(
        Alert.severity,
        func.count(Alert.id).label('count')
    ).filter_by(is_resolved=False).group_by(Alert.severity).all()

    return jsonify({
        'summary': {s: c for s, c in summary},
        'total_unresolved': Alert.query.filter_by(is_resolved=False).count()
    }), 200
