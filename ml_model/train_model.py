#!/usr/bin/env python3
# ============================================================
# ml_model/train_model.py
# ML Training Script
# Models: Random Forest + Isolation Forest
# Dataset: Synthetic NSL-KDD style data (or real NSL-KDD)
# ============================================================

import numpy as np
import pandas as pd
import pickle
import os
import json
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')

# ── scikit-learn ─────────────────────────────────────────────
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, f1_score
)

# ── Visualization ─────────────────────────────────────────────
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

print("=" * 65)
print("  AI Cyber Threat Intelligence — Model Training")
print("=" * 65)

# ── Constants ────────────────────────────────────────────────
MODEL_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH   = os.path.join(MODEL_DIR, '..', 'backend', 'data', 'nsl_kdd_sample.csv')
REPORT_DIR  = os.path.join(MODEL_DIR, 'reports')
os.makedirs(REPORT_DIR, exist_ok=True)

ATTACK_LABELS = {
    'normal':    'Normal',
    'dos':       'DoS',
    'ddos':      'DDoS',
    'probe':     'Probe',
    'portscan':  'PortScan',
    'bruteforce':'BruteForce',
    'r2l':       'R2L',
    'u2r':       'U2R',
    'sqlinject': 'SQLInjection',
}

LABEL_TO_INT = {v: i for i, v in enumerate(sorted(set(ATTACK_LABELS.values())))}


# ════════════════════════════════════════════════════════════
# 1. DATA GENERATION (NSL-KDD style synthetic dataset)
# ════════════════════════════════════════════════════════════

def generate_synthetic_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """
    Generate a synthetic NSL-KDD-style dataset for training.
    Each class has statistically distinct feature distributions.
    """
    np.random.seed(42)
    records = []

    class_configs = {
        'Normal':       {'n': int(n_samples*0.40), 'bytes': (500,5000),   'pkts': (10,200),  'dur': (1,120)},
        'DoS':          {'n': int(n_samples*0.12), 'bytes': (50000,1e6),  'pkts': (2000,50000),'dur': (0.01,5)},
        'DDoS':         {'n': int(n_samples*0.08), 'bytes': (1e6,1e7),    'pkts': (50000,1e6),'dur': (0.001,2)},
        'Probe':        {'n': int(n_samples*0.09), 'bytes': (64,512),     'pkts': (1,10),    'dur': (0.001,0.5)},
        'PortScan':     {'n': int(n_samples*0.06), 'bytes': (40,200),     'pkts': (1,4),     'dur': (0.001,0.1)},
        'BruteForce':   {'n': int(n_samples*0.07), 'bytes': (200,1000),   'pkts': (2,20),    'dur': (0.5,5)},
        'R2L':          {'n': int(n_samples*0.08), 'bytes': (100,800),    'pkts': (2,15),    'dur': (0.1,10)},
        'U2R':          {'n': int(n_samples*0.05), 'bytes': (300,2000),   'pkts': (5,30),    'dur': (0.2,8)},
        'SQLInjection': {'n': int(n_samples*0.05), 'bytes': (200,1500),   'pkts': (3,20),    'dur': (0.1,3)},
    }

    protocols = ['TCP', 'UDP', 'ICMP']
    services  = ['http', 'https', 'ftp', 'ssh', 'smtp', 'dns', 'other']
    protocol_weights = {
        'Normal': [0.6, 0.3, 0.1], 'DoS': [0.2, 0.2, 0.6],
        'DDoS': [0.3, 0.4, 0.3],   'Probe': [0.4, 0.3, 0.3],
        'PortScan': [0.7, 0.2, 0.1], 'BruteForce': [0.9, 0.1, 0.0],
        'R2L': [0.8, 0.2, 0.0],    'U2R': [0.9, 0.1, 0.0],
        'SQLInjection': [0.9, 0.1, 0.0],
    }
    dst_ports = {
        'Normal': [80, 443, 8080, 22, 53],
        'DoS': [80, 443, 53, 25],
        'DDoS': [80, 443, 53],
        'Probe': [22, 23, 25, 80, 443, 3306, 8080],
        'PortScan': [22, 23, 3306, 6379, 1433, 5900],
        'BruteForce': [22, 3389, 23, 21],
        'R2L': [80, 443, 22, 8080],
        'U2R': [22, 8080, 4444],
        'SQLInjection': [80, 443, 8080, 3306],
    }

    for label, cfg in class_configs.items():
        n = cfg['n']
        proto_w = protocol_weights.get(label, [0.6, 0.3, 0.1])
        ports    = dst_ports.get(label, [80, 443])

        for _ in range(n):
            dur = np.random.uniform(*cfg['dur'])
            bsent = int(np.random.uniform(*cfg['bytes']))
            brecv = int(bsent * np.random.uniform(0.1, 0.8))
            psent = int(np.random.uniform(*cfg['pkts']))
            precv = int(psent * np.random.uniform(0.1, 0.7))
            proto = np.random.choice(protocols, p=proto_w)
            svc   = np.random.choice(services)
            dport = np.random.choice(ports)
            sport = np.random.randint(1024, 65535)

            records.append({
                'duration':         round(dur, 4),
                'bytes_sent':       bsent,
                'bytes_received':   brecv,
                'packets_sent':     psent,
                'packets_received': precv,
                'source_port':      sport,
                'destination_port': dport,
                'protocol':         proto,
                'service':          svc,
                'label':            label,
            })

    df = pd.DataFrame(records).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"✅ Generated {len(df):,} samples")
    print(df['label'].value_counts())
    return df


# ════════════════════════════════════════════════════════════
# 2. PREPROCESSING
# ════════════════════════════════════════════════════════════

def preprocess(df: pd.DataFrame):
    """One-hot encode categoricals, scale numerics."""
    print("\n[2/5] Preprocessing...")

    # One-hot encode protocol and service
    df = pd.get_dummies(df, columns=['protocol', 'service'], drop_first=False)

    # Ensure all expected columns exist (fill 0 if missing)
    expected_cols = [
        'duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
        'source_port', 'destination_port',
        'protocol_TCP', 'protocol_UDP', 'protocol_ICMP',
        'service_http', 'service_https', 'service_ftp',
        'service_ssh', 'service_smtp', 'service_dns', 'service_other',
    ]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = 0

    feature_cols = expected_cols
    X = df[feature_cols].values.astype(np.float32)
    y_labels = df['label'].values

    # Encode labels to integers
    le = LabelEncoder()
    le.fit(sorted(set(y_labels)))
    y = le.transform(y_labels)

    print(f"   Features shape: {X.shape}")
    print(f"   Label classes:  {list(le.classes_)}")

    return X, y, le, feature_cols


# ════════════════════════════════════════════════════════════
# 3. TRAIN / EVALUATE
# ════════════════════════════════════════════════════════════

def train_random_forest(X_train, y_train, X_test, y_test, le):
    """Train RF and print evaluation metrics."""
    print("\n[3/5] Training Random Forest Classifier...")

    rf = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',
        n_jobs=-1,
        random_state=42,
        class_weight='balanced'
    )
    rf.fit(X_train, y_train)

    # Evaluate
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1  = f1_score(y_test, y_pred, average='weighted')

    print(f"\n  ✅ Accuracy  : {acc*100:.2f}%")
    print(f"  ✅ F1 Score  : {f1*100:.2f}%")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))

    # Save metrics
    metrics = {
        'model': 'RandomForest',
        'accuracy': round(acc, 4),
        'f1_score': round(f1, 4),
        'n_estimators': rf.n_estimators,
        'trained_at': datetime.now().isoformat(),
        'classes': list(le.classes_)
    }
    with open(os.path.join(REPORT_DIR, 'rf_metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)

    # Confusion matrix plot
    _plot_confusion_matrix(confusion_matrix(y_test, y_pred), le.classes_)

    # Feature importance plot
    _plot_feature_importance(rf, expected_feature_cols)

    return rf


def train_isolation_forest(X_train):
    """Train Isolation Forest for anomaly detection."""
    print("\n[4/5] Training Isolation Forest (Anomaly Detection)...")

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.15,     # 15% expected anomalies
        max_features=1.0,
        random_state=42,
        n_jobs=-1
    )
    iso.fit(X_train)

    # Quick sanity check
    sample_scores = iso.score_samples(X_train[:100])
    print(f"   Anomaly score range: [{sample_scores.min():.3f}, {sample_scores.max():.3f}]")
    print("   ✅ Isolation Forest trained")

    return iso


def _plot_confusion_matrix(cm, class_names):
    plt.figure(figsize=(10, 8), facecolor='#0d1117')
    ax = plt.gca()
    ax.set_facecolor('#0d1117')

    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=class_names, yticklabels=class_names,
        linewidths=0.5, ax=ax,
        annot_kws={'size': 9, 'color': 'white'}
    )
    plt.title('Confusion Matrix — Random Forest', color='white', fontsize=14, pad=10)
    plt.xlabel('Predicted', color='#8e8e93', fontsize=11)
    plt.ylabel('Actual', color='#8e8e93', fontsize=11)
    plt.xticks(rotation=30, ha='right', color='#8e8e93', fontsize=8)
    plt.yticks(rotation=0, color='#8e8e93', fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, 'confusion_matrix.png'), dpi=120, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print("   📊 Confusion matrix saved to reports/confusion_matrix.png")


def _plot_feature_importance(rf, feature_names):
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1][:12]

    plt.figure(figsize=(10, 5), facecolor='#0d1117')
    ax = plt.gca()
    ax.set_facecolor('#0d1117')

    bars = ax.bar(
        range(len(indices)),
        importances[indices],
        color='#00f5ff', edgecolor='none'
    )
    ax.set_xticks(range(len(indices)))
    ax.set_xticklabels([feature_names[i] for i in indices], rotation=40, ha='right',
                        color='#8e8e93', fontsize=8)
    ax.set_title('Top Feature Importances — Random Forest', color='white', fontsize=13, pad=10)
    ax.set_ylabel('Importance', color='#8e8e93')
    ax.spines['bottom'].set_color('#2d2d2f')
    ax.spines['left'].set_color('#2d2d2f')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(colors='#8e8e93')
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, 'feature_importance.png'), dpi=120, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print("   📊 Feature importance saved to reports/feature_importance.png")


# ════════════════════════════════════════════════════════════
# 4. SAVE ARTIFACTS
# ════════════════════════════════════════════════════════════

def save_artifacts(rf, iso, scaler, le, feature_cols):
    """Pickle all model artifacts."""
    print("\n[5/5] Saving model artifacts...")

    with open(os.path.join(MODEL_DIR, 'rf_model.pkl'), 'wb') as f:
        pickle.dump(rf, f, protocol=4)

    with open(os.path.join(MODEL_DIR, 'iso_model.pkl'), 'wb') as f:
        pickle.dump(iso, f, protocol=4)

    with open(os.path.join(MODEL_DIR, 'scaler.pkl'), 'wb') as f:
        pickle.dump(scaler, f, protocol=4)

    with open(os.path.join(MODEL_DIR, 'label_encoder.pkl'), 'wb') as f:
        pickle.dump(le, f, protocol=4)

    # Save feature column list for inference
    with open(os.path.join(MODEL_DIR, 'feature_columns.json'), 'w') as f:
        json.dump(feature_cols, f)

    print("   ✅ rf_model.pkl")
    print("   ✅ iso_model.pkl")
    print("   ✅ scaler.pkl")
    print("   ✅ label_encoder.pkl")
    print("   ✅ feature_columns.json")


# ════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════
expected_feature_cols = [
    'duration', 'bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
    'source_port', 'destination_port',
    'protocol_TCP', 'protocol_UDP', 'protocol_ICMP',
    'service_http', 'service_https', 'service_ftp',
    'service_ssh', 'service_smtp', 'service_dns', 'service_other',
]

if __name__ == '__main__':
    # 1. Load or generate data
    print("\n[1/5] Loading dataset...")
    if os.path.exists(DATA_PATH):
        print(f"   Loading from: {DATA_PATH}")
        df = pd.read_csv(DATA_PATH)
    else:
        print("   No dataset found — generating synthetic NSL-KDD style data")
        df = generate_synthetic_dataset(n_samples=8000)

    # 2. Preprocess
    X, y, le, feature_cols = preprocess(df)

    # 3. Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # 4. Scale
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    # 5. Train
    rf  = train_random_forest(X_train_s, y_train, X_test_s, y_test, le)
    iso = train_isolation_forest(X_train_s)

    # 6. Save
    save_artifacts(rf, iso, scaler, le, feature_cols)

    print("\n" + "=" * 65)
    print("  ✅ Training complete! Models saved to ml_model/")
    print("=" * 65)
