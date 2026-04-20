# ============================================================
# backend/routes/prediction_routes.py
# ML Prediction Routes: /predict, /simulate
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
from model.predictor import predict_attack
from utils.log_generator import generate_single_log, save_log_to_db
import logging

prediction_bp = Blueprint('prediction', __name__)
logger = logging.getLogger(__name__)


@prediction_bp.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    """
    POST /api/predict
    Body: network log feature dict
    Returns: ML prediction + risk assessment
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    required = ['duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received']
    missing = [f for f in required if f not in data]
    if missing:
        return jsonify({'error': f'Missing fields: {missing}'}), 400

    try:
        result = predict_attack(data)
        return jsonify({
            'success': True,
            'prediction': result
        }), 200
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({'error': str(e)}), 500


@prediction_bp.route('/simulate', methods=['POST'])
@jwt_required()
def simulate_and_predict():
    """
    POST /api/simulate
    Generates a synthetic network log, saves to DB, and returns prediction.
    Useful for real-time dashboard simulation.
    """
    try:
        log_data = generate_single_log()
        result = save_log_to_db(log_data)
        return jsonify({
            'success': True,
            'log': {k: v for k, v in log_data.items() if not k.startswith('_')},
            'prediction': result.get('prediction', {})
        }), 201
    except Exception as e:
        logger.error(f"Simulation error: {e}")
        return jsonify({'error': str(e)}), 500


@prediction_bp.route('/bulk-simulate', methods=['POST'])
@jwt_required()
def bulk_simulate():
    """
    POST /api/bulk-simulate
    Body: { "count": 10 }
    Generates N logs and returns summary.
    """
    data = request.get_json(silent=True) or {}
    count = min(int(data.get('count', 5)), 50)  # Cap at 50

    results = []
    errors = 0

    for _ in range(count):
        try:
            log_data = generate_single_log()
            result = save_log_to_db(log_data)
            results.append({
                'source_ip': log_data.get('source_ip'),
                'prediction': result.get('prediction', {})
            })
        except Exception as e:
            errors += 1
            logger.error(f"Bulk sim error: {e}")

    attack_types = [r['prediction'].get('attack_type', 'Unknown') for r in results]
    from collections import Counter
    summary = Counter(attack_types)

    return jsonify({
        'success': True,
        'generated': len(results),
        'errors': errors,
        'summary': dict(summary),
        'results': results
    }), 201


@prediction_bp.route('/predictions', methods=['GET'])
@jwt_required()
def get_predictions():
    """
    GET /api/predictions
    Query params: ?page=1&limit=20&risk_level=HIGH&attack_type=DoS
    """
    from models import AttackPrediction

    page = int(request.args.get('page', 1))
    limit = min(int(request.args.get('limit', 20)), 100)
    risk_level = request.args.get('risk_level')
    attack_type = request.args.get('attack_type')

    query = AttackPrediction.query

    if risk_level:
        query = query.filter_by(risk_level=risk_level.upper())
    if attack_type:
        query = query.filter_by(attack_type=attack_type)

    pagination = query.order_by(AttackPrediction.timestamp.desc()).paginate(
        page=page, per_page=limit, error_out=False
    )

    return jsonify({
        'predictions': [p.to_dict() for p in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200


@prediction_bp.route('/blocked-ips', methods=['GET'])
@jwt_required()
def get_blocked_ips():
    """GET /api/blocked-ips — list all blocked IPs (firewall)."""
    from models import BlockedIP

    active_only = request.args.get('active', 'true').lower() == 'true'
    query = BlockedIP.query
    if active_only:
        query = query.filter_by(is_active=True)

    blocked = query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({'blocked_ips': [b.to_dict() for b in blocked]}), 200


@prediction_bp.route('/blocked-ips/<int:ip_id>/unblock', methods=['POST'])
@jwt_required()
def unblock_ip(ip_id):
    """POST /api/blocked-ips/{id}/unblock — remove IP from firewall."""
    from app import db
    from models import BlockedIP
    from datetime import datetime

    blocked = BlockedIP.query.get_or_404(ip_id)
    blocked.is_active = False
    blocked.unblocked_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': f'IP {blocked.ip_address} unblocked successfully',
        'ip': blocked.to_dict()
    }), 200
