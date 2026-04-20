# ============================================================
# backend/model/predictor.py
# ML Model Loader & Prediction Engine
# ============================================================

import pickle
import os
import numpy as np
import logging
from utils.risk_scorer import compute_risk_score

logger = logging.getLogger(__name__)

# ── Feature columns expected by the model ───────────────────
FEATURE_COLUMNS = [
    'duration', 'bytes_sent', 'bytes_received',
    'packets_sent', 'packets_received',
    'source_port', 'destination_port',
    'protocol_TCP', 'protocol_UDP', 'protocol_ICMP',
    'service_http', 'service_https', 'service_ftp',
    'service_ssh', 'service_smtp', 'service_dns', 'service_other',
]

# Attack type label map
LABEL_MAP = {
    0: 'Normal',
    1: 'DoS',
    2: 'DDoS',
    3: 'Probe',
    4: 'PortScan',
    5: 'BruteForce',
    6: 'R2L',
    7: 'U2R',
    8: 'SQLInjection',
}

# Global model cache (loaded once)
_rf_model = None
_iso_model = None
_scaler = None


def _get_model_dir():
    return os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        'ml_model'
    )


def load_models():
    """Load Random Forest + Isolation Forest + Scaler from disk."""
    global _rf_model, _iso_model, _scaler

    model_dir = _get_model_dir()
    rf_path  = os.path.join(model_dir, 'rf_model.pkl')
    iso_path = os.path.join(model_dir, 'iso_model.pkl')
    scaler_path = os.path.join(model_dir, 'scaler.pkl')

    if os.path.exists(rf_path):
        with open(rf_path, 'rb') as f:
            _rf_model = pickle.load(f)
        logger.info("✅ Random Forest model loaded")
    else:
        logger.warning("⚠️  RF model not found — using rule-based fallback")

    if os.path.exists(iso_path):
        with open(iso_path, 'rb') as f:
            _iso_model = pickle.load(f)
        logger.info("✅ Isolation Forest model loaded")

    if os.path.exists(scaler_path):
        with open(scaler_path, 'rb') as f:
            _scaler = pickle.load(f)
        logger.info("✅ Scaler loaded")


def _extract_features(log_data: dict) -> np.ndarray:
    """Convert raw log dict into model feature vector."""
    protocol = log_data.get('protocol', 'TCP').upper()
    service = log_data.get('service', 'http').lower()

    features = [
        float(log_data.get('duration', 0)),
        float(log_data.get('bytes_sent', 0)),
        float(log_data.get('bytes_received', 0)),
        float(log_data.get('packets_sent', 0)),
        float(log_data.get('packets_received', 0)),
        float(log_data.get('source_port', 0)),
        float(log_data.get('destination_port', 80)),
        1.0 if protocol == 'TCP'  else 0.0,
        1.0 if protocol == 'UDP'  else 0.0,
        1.0 if protocol == 'ICMP' else 0.0,
        1.0 if service == 'http'  else 0.0,
        1.0 if service == 'https' else 0.0,
        1.0 if service == 'ftp'   else 0.0,
        1.0 if service == 'ssh'   else 0.0,
        1.0 if service == 'smtp'  else 0.0,
        1.0 if service == 'dns'   else 0.0,
        1.0 if service not in ('http','https','ftp','ssh','smtp','dns') else 0.0,
    ]
    return np.array(features).reshape(1, -1)


def predict_attack(log_data: dict) -> dict:
    """
    Main prediction function.
    1. Extract features
    2. Run Random Forest (or rule-based fallback)
    3. Run Isolation Forest anomaly detection
    4. Compute risk score
    Returns full prediction dict.
    """
    global _rf_model, _iso_model, _scaler

    # Lazy load
    if _rf_model is None and _iso_model is None:
        load_models()

    features = _extract_features(log_data)

    # ── Random Forest ────────────────────────────────────────
    if _rf_model is not None:
        scaled = _scaler.transform(features) if _scaler else features
        label_idx = int(_rf_model.predict(scaled)[0])
        probas = _rf_model.predict_proba(scaled)[0]
        attack_type = LABEL_MAP.get(label_idx, 'Unknown')
        confidence = float(np.max(probas))
        model_used = 'RandomForest'
    else:
        # Rule-based fallback when model not trained yet
        attack_type, confidence = _rule_based_prediction(log_data)
        model_used = 'RuleBasedFallback'

    # ── Isolation Forest (Anomaly Detection) ─────────────────
    is_anomaly = False
    anomaly_score = 0.0
    if _iso_model is not None:
        scaled_iso = _scaler.transform(features) if _scaler else features
        iso_pred = _iso_model.predict(scaled_iso)[0]        # -1 = anomaly, 1 = normal
        anomaly_score = float(_iso_model.score_samples(scaled_iso)[0])
        is_anomaly = iso_pred == -1

    # ── Risk Score ───────────────────────────────────────────
    risk_result = compute_risk_score(
        attack_type=attack_type,
        confidence=confidence,
        bytes_sent=int(log_data.get('bytes_sent', 0)),
        packets_sent=int(log_data.get('packets_sent', 0)),
        destination_port=int(log_data.get('destination_port', 80)),
        protocol=log_data.get('protocol', 'TCP'),
        is_anomaly=is_anomaly,
        anomaly_score=anomaly_score
    )

    return {
        'attack_type': attack_type,
        'confidence': round(confidence, 4),
        'risk_score': risk_result['score'],
        'risk_level': risk_result['level'],
        'risk_factors': risk_result['factors'],
        'model_used': model_used,
        'is_anomaly': is_anomaly,
        'anomaly_score': round(anomaly_score, 4),
        'source_ip': log_data.get('source_ip', 'unknown'),
        'features_used': FEATURE_COLUMNS
    }


def _rule_based_prediction(log_data: dict) -> tuple:
    """
    Fallback rule-based classifier when ML model is not trained.
    Returns (attack_type, confidence).
    """
    import random

    bytes_sent = int(log_data.get('bytes_sent', 0))
    packets = int(log_data.get('packets_sent', 0))
    dst_port = int(log_data.get('destination_port', 80))
    protocol = log_data.get('protocol', 'TCP').upper()
    duration = float(log_data.get('duration', 0))

    # High volume → DoS/DDoS
    if bytes_sent > 500_000 or packets > 20_000:
        return ('DDoS' if packets > 50_000 else 'DoS', random.uniform(0.82, 0.96))

    # Very short, many small packets → PortScan
    if duration < 0.05 and packets < 5 and bytes_sent < 200:
        return ('PortScan', random.uniform(0.78, 0.92))

    # SSH port with repeated medium traffic → BruteForce
    if dst_port == 22 and 200 < bytes_sent < 2000:
        return ('BruteForce', random.uniform(0.75, 0.90))

    # ICMP → Probe
    if protocol == 'ICMP':
        return ('Probe', random.uniform(0.70, 0.85))

    # High port + small traffic → R2L
    if dst_port > 1024 and bytes_sent < 500:
        return ('R2L', random.uniform(0.65, 0.80))

    # Default: Normal
    return ('Normal', random.uniform(0.88, 0.99))
