# ============================================================
# backend/utils/auth.py
# Authentication Utilities: JWT, Brute Force Detection
# ============================================================

from datetime import datetime, timedelta
from flask import request
from flask_jwt_extended import create_access_token, create_refresh_token
import hashlib
import logging

logger = logging.getLogger(__name__)


def get_client_ip():
    """Extract real client IP, handling proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr or '127.0.0.1'


def generate_tokens(user_id: int, username: str, role: str) -> dict:
    """Generate JWT access + refresh token pair."""
    identity = str(user_id)
    additional_claims = {
        'username': username,
        'role': role
    }
    access_token = create_access_token(
        identity=identity,
        additional_claims=additional_claims
    )
    refresh_token = create_refresh_token(
        identity=identity,
        additional_claims=additional_claims
    )
    return {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'Bearer'
    }


def record_login_attempt(username: str, ip_address: str, success: bool):
    """Log login attempt to DB for brute force detection."""
    from app import db
    from models import LoginAttempt

    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        timestamp=datetime.utcnow(),
        success=success,
        user_agent=request.headers.get('User-Agent', '')[:512]
    )
    db.session.add(attempt)
    db.session.commit()
    logger.info(f"Login attempt: user={username}, ip={ip_address}, success={success}")


def check_brute_force(ip_address: str, window_seconds: int = 300, threshold: int = 5) -> dict:
    """
    Check if an IP has exceeded the failed login threshold.
    Returns dict with is_blocked, attempts, remaining_time.
    """
    from models import LoginAttempt, BlockedIP
    from app import db

    # Check if IP is already hard-blocked
    blocked = BlockedIP.query.filter_by(ip_address=ip_address, is_active=True).first()
    if blocked:
        return {
            'is_blocked': True,
            'reason': 'IP is in firewall blocklist',
            'attempts': blocked.attack_count,
            'permanent': True
        }

    # Count recent failed attempts
    cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
    failed_count = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff
    ).count()

    if failed_count >= threshold:
        # Auto-block the IP
        _auto_block_ip(ip_address, f'Brute force: {failed_count} failed attempts in {window_seconds}s')
        _create_brute_force_alert(ip_address, failed_count)
        return {
            'is_blocked': True,
            'reason': f'Too many failed login attempts ({failed_count})',
            'attempts': failed_count,
            'permanent': False
        }

    return {
        'is_blocked': False,
        'attempts': failed_count,
        'remaining': threshold - failed_count
    }


def _auto_block_ip(ip_address: str, reason: str):
    """Automatically block an IP in the simulated firewall."""
    from app import db
    from models import BlockedIP

    existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        existing.is_active = True
        existing.attack_count += 1
        existing.reason = reason
    else:
        blocked = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            is_active=True
        )
        db.session.add(blocked)

    try:
        db.session.commit()
        logger.warning(f"🚫 Auto-blocked IP: {ip_address} | Reason: {reason}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to block IP {ip_address}: {e}")


def _create_brute_force_alert(ip_address: str, attempt_count: int):
    """Create a HIGH severity alert for brute force detection."""
    from app import db
    from models import Alert

    alert = Alert(
        alert_type='Brute Force Attack',
        severity='HIGH',
        source_ip=ip_address,
        message=f'Brute force attack detected from {ip_address}: {attempt_count} failed login attempts',
        is_resolved=False
    )
    db.session.add(alert)
    try:
        db.session.commit()
    except:
        db.session.rollback()
