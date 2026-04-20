# ============================================================
# backend/app.py
# Flask Application Entry Point
# AI Cyber Threat Intelligence & Attack Prediction System
# ============================================================

from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from config.config import get_config
import logging
import os
import sys

# When executed as "python app.py", expose this module as "app" so
# imports like "from app import db" reuse the same extension instance.
if __name__ == '__main__':
    sys.modules['app'] = sys.modules[__name__]

# ── Initialize extensions (no app yet) ──────────────────────
db = SQLAlchemy()
jwt = JWTManager()


def create_app(config_class=None):
    """Application factory pattern."""
    app = Flask(__name__)

    # Load config
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    app.logger.setLevel(logging.INFO)

    # Extensions
    db.init_app(app)
    jwt.init_app(app)
    CORS(app, origins=app.config.get('CORS_ORIGINS', ['http://localhost:3000']),
         supports_credentials=True)

    # ── JWT Error Handlers ───────────────────────────────────
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({'error': 'Token has expired', 'code': 'TOKEN_EXPIRED'}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({'error': 'Invalid token', 'code': 'INVALID_TOKEN'}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({'error': 'Authorization token required', 'code': 'TOKEN_MISSING'}), 401

    # ── Register Blueprints ──────────────────────────────────
    from routes.auth_routes import auth_bp
    from routes.prediction_routes import prediction_bp
    from routes.log_routes import log_bp
    from routes.alert_routes import alert_bp
    from routes.analytics_routes import analytics_bp

    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(prediction_bp, url_prefix='/api')
    app.register_blueprint(log_bp, url_prefix='/api')
    app.register_blueprint(alert_bp, url_prefix='/api')
    app.register_blueprint(analytics_bp, url_prefix='/api')

    # ── Health Check ─────────────────────────────────────────
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'service': 'AI Cyber Threat Intelligence System',
            'version': '1.0.0'
        })

    @app.route('/', methods=['GET'])
    def root_info():
        return jsonify({
            'message': 'Backend is running',
            'health': '/api/health',
            'api_base': '/api'
        })

    @app.route('/favicon.ico', methods=['GET'])
    def favicon():
        return ('', 204)

    # ── Create DB Tables ─────────────────────────────────────
    with app.app_context():
        import models  # noqa: F401 - ensure model metadata is registered
        db.create_all()
        _seed_demo_data(app)
        app.logger.info("✅ Database tables created successfully")

    return app


def _seed_demo_data(app):
    """Insert demo data so the dashboard has content on first run."""
    from models import User, NetworkLog, AttackPrediction, Alert, BlockedIP
    from werkzeug.security import generate_password_hash
    import random, datetime

    # Seed admin user
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@cyberai.local',
            password_hash=generate_password_hash('Admin@123'),
            role='admin'
        )
        analyst = User(
            username='analyst1',
            email='analyst@cyberai.local',
            password_hash=generate_password_hash('Admin@123'),
            role='analyst'
        )
        db.session.add_all([admin, analyst])
        db.session.commit()
        app.logger.info("✅ Demo users seeded (admin / Admin@123)")

    # Seed logs if empty
    if NetworkLog.query.count() < 10:
        _seed_logs_and_predictions(app)


def _seed_logs_and_predictions(app):
    """Generate 200 synthetic network logs + predictions for demo."""
    from models import NetworkLog, AttackPrediction, Alert, BlockedIP
    import random, datetime

    attack_types = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R', 'DDoS', 'BruteForce', 'PortScan']
    protocols = ['TCP', 'UDP', 'ICMP']
    services = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'https', 'pop3']
    fake_ips = [
        '192.168.1.' + str(i) for i in range(1, 20)
    ] + ['10.0.0.' + str(i) for i in range(1, 15)] + [
        '172.16.0.' + str(i) for i in range(1, 10)
    ]
    geo = [
        ('United States', 'New York', 40.71, -74.00),
        ('China', 'Beijing', 39.90, 116.40),
        ('Russia', 'Moscow', 55.75, 37.61),
        ('Germany', 'Berlin', 52.52, 13.40),
        ('India', 'Mumbai', 19.07, 72.87),
        ('Brazil', 'São Paulo', -23.55, -46.63),
        ('United Kingdom', 'London', 51.50, -0.12),
    ]

    logs = []
    predictions = []
    alerts = []

    now = datetime.datetime.utcnow()

    for i in range(200):
        ts = now - datetime.timedelta(minutes=random.randint(1, 43200))  # last 30 days
        src_ip = random.choice(fake_ips)
        attack = random.choices(
            attack_types,
            weights=[45, 15, 10, 8, 5, 10, 4, 3]
        )[0]
        country_info = random.choice(geo)
        protocol = random.choice(protocols)

        log = NetworkLog(
            timestamp=ts,
            source_ip=src_ip,
            destination_ip='10.10.10.' + str(random.randint(1, 50)),
            source_port=random.randint(1024, 65535),
            destination_port=random.choice([80, 443, 22, 21, 25, 53, 3306]),
            protocol=protocol,
            duration=round(random.uniform(0, 60), 2),
            bytes_sent=random.randint(0, 100000),
            bytes_received=random.randint(0, 50000),
            packets_sent=random.randint(1, 1000),
            packets_received=random.randint(1, 500),
            service=random.choice(services),
            action='DENY' if attack != 'Normal' else 'ALLOW',
            country=country_info[0],
            city=country_info[1],
            latitude=country_info[2],
            longitude=country_info[3]
        )
        logs.append(log)

    db.session.bulk_save_objects(logs)
    db.session.commit()

    # Create predictions for each log
    saved_logs = NetworkLog.query.all()
    risk_map = {'Normal': (5, 'LOW'), 'DoS': (78, 'HIGH'), 'Probe': (55, 'MEDIUM'),
                'R2L': (82, 'CRITICAL'), 'U2R': (90, 'CRITICAL'), 'DDoS': (88, 'CRITICAL'),
                'BruteForce': (70, 'HIGH'), 'PortScan': (60, 'MEDIUM')}

    for log in saved_logs:
        attack = random.choices(attack_types, weights=[45, 15, 10, 8, 5, 10, 4, 3])[0]
        base_risk, risk_level = risk_map.get(attack, (30, 'LOW'))
        confidence = round(random.uniform(0.75, 0.99), 3)
        risk_score = round(base_risk + random.uniform(-10, 10), 1)
        risk_score = max(0, min(100, risk_score))
        risk_level_final = (
            'CRITICAL' if risk_score >= 85 else
            'HIGH' if risk_score >= 65 else
            'MEDIUM' if risk_score >= 40 else 'LOW'
        )

        pred = AttackPrediction(
            log_id=log.id,
            timestamp=log.timestamp,
            source_ip=log.source_ip,
            attack_type=attack,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level_final,
            is_anomaly=risk_score > 70,
            anomaly_score=round(random.uniform(-0.5, 0.5), 3)
        )
        predictions.append(pred)

        if attack != 'Normal' and risk_score > 60:
            alert = Alert(
                timestamp=log.timestamp,
                alert_type=f'{attack} Detected',
                severity='CRITICAL' if risk_score >= 85 else 'HIGH' if risk_score >= 65 else 'WARNING',
                source_ip=log.source_ip,
                message=f'{attack} attack detected from {log.source_ip} with {confidence*100:.1f}% confidence',
                is_resolved=random.random() > 0.7
            )
            alerts.append(alert)

    db.session.bulk_save_objects(predictions)
    db.session.bulk_save_objects(alerts)

    # Blocked IPs
    blocked = [
        BlockedIP(ip_address='192.168.1.100', reason='Repeated brute force attempts', attack_count=47),
        BlockedIP(ip_address='10.0.0.55', reason='Port scan detected', attack_count=12),
        BlockedIP(ip_address='172.16.0.200', reason='DoS attack pattern', attack_count=89),
    ]
    for b in blocked:
        from sqlalchemy.exc import IntegrityError
        try:
            db.session.add(b)
            db.session.commit()
        except:
            db.session.rollback()

    db.session.commit()
    app.logger.info(f"✅ Seeded {len(saved_logs)} logs, {len(predictions)} predictions, {len(alerts)} alerts")


# ── Run ───────────────────────────────────────────────────────
if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=True)
