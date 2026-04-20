# ============================================================
# backend/utils/alert_engine.py
# Rule-based Alert Engine + Email Simulation
# ============================================================

import logging
import smtplib
import json
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger(__name__)


# ── Alert Rules ──────────────────────────────────────────────
ALERT_RULES = [
    {
        'id': 'RULE_001',
        'name': 'Critical Attack Detected',
        'condition': lambda p: p.get('risk_level') == 'CRITICAL',
        'severity': 'CRITICAL',
        'message': lambda p: f"CRITICAL: {p['attack_type']} from {p['source_ip']} (risk={p['risk_score']})"
    },
    {
        'id': 'RULE_002',
        'name': 'High Risk Attack',
        'condition': lambda p: p.get('risk_level') == 'HIGH',
        'severity': 'HIGH',
        'message': lambda p: f"HIGH RISK: {p['attack_type']} attack detected from {p['source_ip']}"
    },
    {
        'id': 'RULE_003',
        'name': 'DDoS Pattern',
        'condition': lambda p: p.get('attack_type') in ('DDoS', 'DoS') and p.get('confidence', 0) > 0.8,
        'severity': 'CRITICAL',
        'message': lambda p: f"DDoS/DoS attack pattern confirmed from {p['source_ip']}"
    },
    {
        'id': 'RULE_004',
        'name': 'Privilege Escalation Attempt',
        'condition': lambda p: p.get('attack_type') == 'U2R',
        'severity': 'CRITICAL',
        'message': lambda p: f"Privilege escalation attempt from {p['source_ip']}"
    },
    {
        'id': 'RULE_005',
        'name': 'Reconnaissance Activity',
        'condition': lambda p: p.get('attack_type') in ('Probe', 'PortScan'),
        'severity': 'WARNING',
        'message': lambda p: f"Reconnaissance: {p['attack_type']} from {p['source_ip']}"
    },
    {
        'id': 'RULE_006',
        'name': 'Remote Access Attempt',
        'condition': lambda p: p.get('attack_type') == 'R2L',
        'severity': 'HIGH',
        'message': lambda p: f"Remote access attempt detected from {p['source_ip']}"
    },
    {
        'id': 'RULE_007',
        'name': 'Anomaly Detected',
        'condition': lambda p: p.get('is_anomaly') and p.get('anomaly_score', 0) < -0.3,
        'severity': 'WARNING',
        'message': lambda p: f"Anomalous behavior from {p['source_ip']} (score={p.get('anomaly_score',0):.3f})"
    },
]


def evaluate_rules(prediction: dict) -> list:
    """
    Evaluate all alert rules against a prediction.
    Returns list of triggered alert dicts.
    """
    triggered = []

    for rule in ALERT_RULES:
        try:
            if rule['condition'](prediction):
                triggered.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'message': rule['message'](prediction),
                    'prediction': prediction
                })
        except Exception as e:
            logger.error(f"Rule {rule['id']} evaluation error: {e}")

    return triggered


def create_alerts_from_prediction(prediction_data: dict, prediction_id: int = None):
    """Evaluate rules and persist alerts to DB."""
    from app import db
    from models import Alert

    triggered = evaluate_rules(prediction_data)
    created = []

    for alert_data in triggered:
        alert = Alert(
            alert_type=alert_data['rule_name'],
            severity=alert_data['severity'],
            source_ip=prediction_data.get('source_ip'),
            message=alert_data['message'],
            details=json.dumps({
                'rule_id': alert_data['rule_id'],
                'attack_type': prediction_data.get('attack_type'),
                'confidence': prediction_data.get('confidence'),
                'risk_score': prediction_data.get('risk_score')
            }),
            prediction_id=prediction_id
        )
        db.session.add(alert)
        created.append(alert_data)

        # Simulate email for CRITICAL alerts
        if alert_data['severity'] == 'CRITICAL':
            simulate_email_alert(alert_data['message'])

    try:
        db.session.commit()
        if created:
            logger.warning(f"⚠️  {len(created)} alert(s) created for {prediction_data.get('source_ip')}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save alerts: {e}")

    return created


def simulate_email_alert(message: str, recipient: str = 'security@cyberai.local'):
    """
    Simulate sending an email alert.
    In production, replace with actual SMTP / SendGrid / SES call.
    """
    email_body = f"""
    ════════════════════════════════════════
    🔴 CYBER THREAT INTELLIGENCE ALERT
    ════════════════════════════════════════
    Time    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
    Alert   : {message}
    System  : AI Cyber Threat Intelligence System
    Action  : Please investigate immediately.
    ════════════════════════════════════════
    """
    logger.info(f"📧 [SIMULATED EMAIL] To: {recipient}\n{email_body}")
    # Actual implementation:
    # msg = MIMEText(email_body)
    # msg['Subject'] = f'🔴 CRITICAL SECURITY ALERT: {message[:60]}'
    # msg['From'] = 'alerts@cyberai.local'
    # msg['To'] = recipient
    # with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
    #     smtp.starttls()
    #     smtp.login(user, password)
    #     smtp.send_message(msg)
