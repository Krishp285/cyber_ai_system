# ============================================================
# backend/routes/auth_routes.py
# Authentication Routes: /login, /logout, /refresh, /me
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, get_jwt,
    create_access_token
)
from werkzeug.security import check_password_hash
from datetime import datetime
from utils.auth import get_client_ip, generate_tokens, record_login_attempt, check_brute_force
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    POST /api/login
    Body: { "username": "...", "password": "..." }
    Returns: { access_token, refresh_token, user }
    """
    from app import db
    from models import User

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    username = data.get('username', '').strip()
    password = data.get('password', '')
    ip_address = get_client_ip()

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    # ── Brute Force Check ────────────────────────────────────
    bf_check = check_brute_force(ip_address)
    if bf_check['is_blocked']:
        logger.warning(f"🚫 Blocked login attempt from {ip_address}")
        return jsonify({
            'error': 'Access denied: ' + bf_check['reason'],
            'code': 'IP_BLOCKED'
        }), 403

    # ── Authenticate ─────────────────────────────────────────
    user = User.query.filter_by(username=username, is_active=True).first()

    if not user or not check_password_hash(user.password_hash, password):
        record_login_attempt(username, ip_address, success=False)
        remaining = bf_check.get('remaining', 5) - 1
        return jsonify({
            'error': 'Invalid username or password',
            'remaining_attempts': max(0, remaining)
        }), 401

    # ── Success ───────────────────────────────────────────────
    record_login_attempt(username, ip_address, success=True)
    user.last_login = datetime.utcnow()
    db.session.commit()

    tokens = generate_tokens(user.id, user.username, user.role)

    logger.info(f"✅ Login: {username} from {ip_address}")
    return jsonify({
        **tokens,
        'user': user.to_dict()
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """POST /api/refresh — get new access token using refresh token."""
    from models import User

    identity = get_jwt_identity()
    claims = get_jwt()
    user = User.query.get(int(identity))

    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 401

    new_access_token = create_access_token(
        identity=identity,
        additional_claims={'username': claims.get('username'), 'role': claims.get('role')}
    )
    return jsonify({'access_token': new_access_token}), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """GET /api/me — return current authenticated user info."""
    from models import User

    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({'user': user.to_dict()}), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """POST /api/logout — client should discard tokens."""
    return jsonify({'message': 'Logged out successfully'}), 200


@auth_bp.route('/users', methods=['GET'])
@jwt_required()
def list_users():
    """GET /api/users — list all users (admin only)."""
    from models import User

    claims = get_jwt()
    if claims.get('role') != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    users = User.query.all()
    return jsonify({'users': [u.to_dict() for u in users]}), 200
