# ============================================================
# backend/models.py
# SQLAlchemy ORM Models
# ============================================================

from app import db
from datetime import datetime
import json


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.Enum('admin', 'analyst', 'viewer'), default='analyst')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }


class NetworkLog(db.Model):
    __tablename__ = 'network_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    duration = db.Column(db.Float, default=0)
    bytes_sent = db.Column(db.Integer, default=0)
    bytes_received = db.Column(db.Integer, default=0)
    packets_sent = db.Column(db.Integer, default=0)
    packets_received = db.Column(db.Integer, default=0)
    flags = db.Column(db.String(50))
    service = db.Column(db.String(50))
    action = db.Column(db.Enum('ALLOW', 'DENY', 'DROP'), default='ALLOW')
    country = db.Column(db.String(50), default='Unknown')
    city = db.Column(db.String(100), default='Unknown')
    latitude = db.Column(db.Float, default=0)
    longitude = db.Column(db.Float, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'duration': self.duration,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'packets_sent': self.packets_sent,
            'packets_received': self.packets_received,
            'service': self.service,
            'action': self.action,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude
        }


class AttackPrediction(db.Model):
    __tablename__ = 'attack_predictions'

    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey('network_logs.id', ondelete='SET NULL'), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    attack_type = db.Column(db.String(100), nullable=False, index=True)
    confidence = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    risk_level = db.Column(db.Enum('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'), nullable=False)
    model_used = db.Column(db.String(50), default='RandomForest')
    is_anomaly = db.Column(db.Boolean, default=False)
    anomaly_score = db.Column(db.Float, default=0)
    features_json = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'log_id': self.log_id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'source_ip': self.source_ip,
            'attack_type': self.attack_type,
            'confidence': self.confidence,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'model_used': self.model_used,
            'is_anomaly': self.is_anomaly,
            'anomaly_score': self.anomaly_score
        }


class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    alert_type = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.Enum('INFO', 'WARNING', 'HIGH', 'CRITICAL'), nullable=False, index=True)
    source_ip = db.Column(db.String(45))
    message = db.Column(db.Text, nullable=False)
    details = db.Column(db.Text)   # JSON string
    is_resolved = db.Column(db.Boolean, default=False, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('attack_predictions.id', ondelete='SET NULL'), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'message': self.message,
            'details': json.loads(self.details) if self.details else None,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'prediction_id': self.prediction_id
        }


class BlockedIP(db.Model):
    __tablename__ = 'blocked_ips'

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    unblocked_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, index=True)
    attack_count = db.Column(db.Integer, default=1)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reason': self.reason,
            'blocked_at': self.blocked_at.isoformat() if self.blocked_at else None,
            'is_active': self.is_active,
            'attack_count': self.attack_count
        }


class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success = db.Column(db.Boolean, default=False)
    user_agent = db.Column(db.String(512))

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'success': self.success
        }


class ThreatForecast(db.Model):
    __tablename__ = 'threat_forecasts'

    id = db.Column(db.Integer, primary_key=True)
    forecast_date = db.Column(db.Date, nullable=False, index=True)
    predicted_attack_type = db.Column(db.String(100))
    predicted_count = db.Column(db.Integer)
    confidence_level = db.Column(db.Float)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    actual_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'forecast_date': self.forecast_date.isoformat() if self.forecast_date else None,
            'predicted_attack_type': self.predicted_attack_type,
            'predicted_count': self.predicted_count,
            'confidence_level': self.confidence_level,
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
            'actual_count': self.actual_count
        }
