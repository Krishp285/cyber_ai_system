# ============================================================
# backend/utils/risk_scorer.py
# Risk Scoring Engine: maps attack features → risk score
# ============================================================

import logging

logger = logging.getLogger(__name__)

# Base risk scores per attack type
ATTACK_BASE_SCORES = {
    'Normal':       5.0,
    'DoS':         72.0,
    'DDoS':        85.0,
    'Probe':       50.0,
    'PortScan':    55.0,
    'BruteForce':  68.0,
    'R2L':         80.0,
    'U2R':         90.0,
    'SQLInjection': 88.0,
    'Unknown':     40.0,
}

# Protocol risk multipliers
PROTOCOL_FACTORS = {
    'TCP':  1.0,
    'UDP':  1.1,
    'ICMP': 1.2,
}

# High-risk destination ports
HIGH_RISK_PORTS = {22, 23, 3306, 1433, 5432, 6379, 27017, 2181}
MEDIUM_RISK_PORTS = {80, 443, 8080, 8443, 21, 25}


def compute_risk_score(
    attack_type: str,
    confidence: float,
    bytes_sent: int = 0,
    packets_sent: int = 0,
    destination_port: int = 80,
    protocol: str = 'TCP',
    is_anomaly: bool = False,
    anomaly_score: float = 0.0,
    **kwargs
) -> dict:
    """
    Compute a 0-100 risk score and classify it.

    Parameters:
        attack_type   : Predicted attack category
        confidence    : ML confidence 0-1
        bytes_sent    : Volume indicator
        packets_sent  : Frequency indicator
        destination_port: Target port
        protocol      : Network protocol
        is_anomaly    : From Isolation Forest
        anomaly_score : Isolation Forest score (negative = more anomalous)

    Returns:
        {'score': float, 'level': str, 'factors': list}
    """
    factors = []
    base = ATTACK_BASE_SCORES.get(attack_type, 40.0)
    score = base

    # Confidence adjustment (±10)
    conf_delta = (confidence - 0.5) * 20
    score += conf_delta
    factors.append(f'Confidence {confidence*100:.1f}% → {conf_delta:+.1f}')

    # Protocol factor
    proto_mult = PROTOCOL_FACTORS.get(protocol, 1.0)
    if proto_mult != 1.0:
        adj = (proto_mult - 1.0) * 10
        score += adj
        factors.append(f'Protocol {protocol} → {adj:+.1f}')

    # Port risk
    if destination_port in HIGH_RISK_PORTS:
        score += 8
        factors.append(f'High-risk port {destination_port} → +8')
    elif destination_port in MEDIUM_RISK_PORTS:
        score += 3
        factors.append(f'Medium-risk port {destination_port} → +3')

    # Traffic volume
    if bytes_sent > 1_000_000:
        score += 10
        factors.append(f'High volume ({bytes_sent:,} bytes) → +10')
    elif bytes_sent > 100_000:
        score += 5
        factors.append(f'Medium volume ({bytes_sent:,} bytes) → +5')

    # Packet rate
    if packets_sent > 10_000:
        score += 8
        factors.append(f'High packet rate ({packets_sent:,}) → +8')

    # Anomaly bonus
    if is_anomaly:
        anomaly_boost = max(0, -anomaly_score * 15)  # negative score = more anomalous
        score += anomaly_boost
        factors.append(f'Anomaly detected (score={anomaly_score:.3f}) → +{anomaly_boost:.1f}')

    # Clamp to [0, 100]
    score = round(max(0.0, min(100.0, score)), 1)

    # Classify
    if score >= 85:
        level = 'CRITICAL'
    elif score >= 65:
        level = 'HIGH'
    elif score >= 40:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return {
        'score': score,
        'level': level,
        'base_score': base,
        'factors': factors
    }


def get_risk_color(level: str) -> str:
    """Return hex color for risk level."""
    return {
        'CRITICAL': '#ff2d55',
        'HIGH':     '#ff6b35',
        'MEDIUM':   '#ffcc00',
        'LOW':      '#30d158'
    }.get(level, '#8e8e93')
