# ============================================================
# backend/utils/log_generator.py
# Real-time Log Simulation Engine
# ============================================================

import random
import datetime
import ipaddress
import logging

logger = logging.getLogger(__name__)

# ── Attack Type Weights ──────────────────────────────────────
ATTACK_TYPES = {
    'Normal':     45,
    'DoS':        12,
    'DDoS':        8,
    'Probe':       9,
    'PortScan':    6,
    'BruteForce':  6,
    'R2L':         7,
    'U2R':         4,
    'SQLInjection': 3,
}

PROTOCOLS = ['TCP', 'UDP', 'ICMP']

SERVICES = {
    80:   'http',
    443:  'https',
    22:   'ssh',
    21:   'ftp',
    25:   'smtp',
    53:   'dns',
    3306: 'mysql',
    8080: 'http-alt',
    110:  'pop3',
    143:  'imap',
}

# Simulated geo-locations for known "attacker" IPs
GEO_DATABASE = [
    ('United States', 'New York',       40.7128,  -74.0060),
    ('China',         'Beijing',        39.9042,  116.4074),
    ('Russia',        'Moscow',         55.7558,   37.6173),
    ('Germany',       'Berlin',         52.5200,   13.4050),
    ('India',         'Mumbai',         19.0760,   72.8777),
    ('Brazil',        'São Paulo',     -23.5505,  -46.6333),
    ('United Kingdom','London',         51.5074,   -0.1278),
    ('France',        'Paris',          48.8566,    2.3522),
    ('Japan',         'Tokyo',          35.6762,  139.6503),
    ('South Korea',   'Seoul',          37.5665,  126.9780),
    ('Iran',          'Tehran',         35.6892,   51.3890),
    ('North Korea',   'Pyongyang',      39.0194,  125.7381),
    ('Netherlands',   'Amsterdam',      52.3676,    4.9041),
    ('Ukraine',       'Kyiv',           50.4501,   30.5234),
    ('Nigeria',       'Lagos',           6.5244,    3.3792),
    ('Australia',     'Sydney',        -33.8688,  151.2093),
]

# Pool of "attacker" IPs
KNOWN_ATTACKER_IPS = [
    '203.0.113.5',   '198.51.100.10',  '192.0.2.15',
    '45.33.32.156',  '89.234.157.254', '115.238.245.32',
    '221.194.47.249','59.63.188.32',   '125.212.217.194',
    '218.92.0.114',  '80.82.77.33',    '162.247.72.199',
]

# Internal "victim" IPs
INTERNAL_IPS = [f'10.0.{i}.{j}' for i in range(0, 5) for j in range(1, 30)]


def generate_single_log() -> dict:
    """
    Generate one synthetic network log entry.
    Returns a dict matching the NetworkLog model fields.
    """
    attack_type = random.choices(
        list(ATTACK_TYPES.keys()),
        weights=list(ATTACK_TYPES.values())
    )[0]

    is_attack = attack_type != 'Normal'

    # Source IP
    if is_attack and random.random() > 0.3:
        src_ip = random.choice(KNOWN_ATTACKER_IPS)
        geo = random.choice(GEO_DATABASE[1:])   # non-US more likely for attackers
    else:
        src_ip = _random_internal_ip()
        geo = random.choice(GEO_DATABASE)

    dst_ip = random.choice(INTERNAL_IPS)
    dst_port = random.choice(list(SERVICES.keys()))
    src_port = random.randint(1024, 65535)

    # Adjust traffic stats based on attack type
    if attack_type in ('DoS', 'DDoS'):
        bytes_sent = random.randint(100000, 10000000)
        packets_sent = random.randint(5000, 100000)
        duration = round(random.uniform(0.01, 5.0), 3)
    elif attack_type == 'PortScan':
        bytes_sent = random.randint(64, 512)
        packets_sent = random.randint(1, 5)
        duration = round(random.uniform(0.001, 0.1), 3)
    elif attack_type == 'BruteForce':
        bytes_sent = random.randint(200, 1000)
        packets_sent = random.randint(2, 20)
        duration = round(random.uniform(0.5, 3.0), 3)
    else:
        bytes_sent = random.randint(64, 50000)
        packets_sent = random.randint(1, 500)
        duration = round(random.uniform(0, 120), 3)

    return {
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'source_ip': src_ip,
        'destination_ip': dst_ip,
        'source_port': src_port,
        'destination_port': dst_port,
        'protocol': 'ICMP' if attack_type == 'DoS' else random.choice(PROTOCOLS),
        'duration': duration,
        'bytes_sent': bytes_sent,
        'bytes_received': random.randint(0, bytes_sent // 2 + 1),
        'packets_sent': packets_sent,
        'packets_received': random.randint(0, packets_sent // 2 + 1),
        'service': SERVICES.get(dst_port, 'other'),
        'action': 'DENY' if is_attack else 'ALLOW',
        'country': geo[0],
        'city': geo[1],
        'latitude': geo[2],
        'longitude': geo[3],
        # Metadata for prediction
        '_attack_type': attack_type,
        '_is_attack': is_attack,
    }


def generate_bulk_logs(count: int = 10) -> list:
    """Generate multiple log entries."""
    return [generate_single_log() for _ in range(count)]


def save_log_to_db(log_data: dict):
    """Persist a generated log entry to DB and run prediction."""
    from app import db
    from models import NetworkLog, AttackPrediction, Alert, BlockedIP
    from model.predictor import predict_attack

    try:
        # Strip internal metadata keys
        attack_type = log_data.pop('_attack_type', 'Unknown')
        log_data.pop('_is_attack', None)

        # Save log
        log = NetworkLog(
            timestamp=datetime.datetime.utcnow(),
            source_ip=log_data['source_ip'],
            destination_ip=log_data['destination_ip'],
            source_port=log_data['source_port'],
            destination_port=log_data['destination_port'],
            protocol=log_data['protocol'],
            duration=log_data['duration'],
            bytes_sent=log_data['bytes_sent'],
            bytes_received=log_data['bytes_received'],
            packets_sent=log_data['packets_sent'],
            packets_received=log_data['packets_received'],
            service=log_data['service'],
            action=log_data['action'],
            country=log_data['country'],
            city=log_data['city'],
            latitude=log_data['latitude'],
            longitude=log_data['longitude']
        )
        db.session.add(log)
        db.session.flush()  # get log.id

        # Run ML prediction
        prediction_result = predict_attack(log_data)

        pred = AttackPrediction(
            log_id=log.id,
            source_ip=log_data['source_ip'],
            attack_type=prediction_result['attack_type'],
            confidence=prediction_result['confidence'],
            risk_score=prediction_result['risk_score'],
            risk_level=prediction_result['risk_level'],
            model_used=prediction_result['model_used'],
            is_anomaly=prediction_result['is_anomaly'],
            anomaly_score=prediction_result.get('anomaly_score', 0)
        )
        db.session.add(pred)
        db.session.flush()

        # Create alert if needed
        if prediction_result['risk_level'] in ('HIGH', 'CRITICAL'):
            alert = Alert(
                alert_type=f"{prediction_result['attack_type']} Detected",
                severity='CRITICAL' if prediction_result['risk_level'] == 'CRITICAL' else 'HIGH',
                source_ip=log_data['source_ip'],
                message=(f"{prediction_result['attack_type']} detected from "
                         f"{log_data['source_ip']} | "
                         f"Confidence: {prediction_result['confidence']*100:.1f}% | "
                         f"Risk: {prediction_result['risk_score']:.1f}"),
                prediction_id=pred.id
            )
            db.session.add(alert)

            # Auto-block highly dangerous IPs
            if prediction_result['risk_score'] >= 85:
                _maybe_block_ip(log_data['source_ip'],
                                f"Auto-blocked: {prediction_result['attack_type']}")

        db.session.commit()
        return {**log_data, 'log_id': log.id, 'prediction': prediction_result}

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving log: {e}")
        raise


def _random_internal_ip() -> str:
    return f'10.0.{random.randint(0,4)}.{random.randint(1,50)}'


def _maybe_block_ip(ip: str, reason: str):
    """Block IP if not already blocked."""
    from app import db
    from models import BlockedIP

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        existing.attack_count += 1
        existing.is_active = True
    else:
        db.session.add(BlockedIP(
            ip_address=ip,
            reason=reason,
            is_active=True
        ))
    try:
        db.session.commit()
    except:
        db.session.rollback()
