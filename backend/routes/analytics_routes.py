# ============================================================
# backend/routes/analytics_routes.py
# Data Science Analytics Routes: /analytics
# ============================================================

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required
from datetime import datetime, timedelta
import logging
import io

analytics_bp = Blueprint('analytics', __name__)
logger = logging.getLogger(__name__)


@analytics_bp.route('/analytics/overview', methods=['GET'])
@jwt_required()
def analytics_overview():
    """
    GET /api/analytics/overview
    Returns all key analytics data for the Analytics page.
    """
    from models import AttackPrediction, NetworkLog, Alert
    from app import db
    from sqlalchemy import func, cast, Date

    # ── Attacks per day (last 30 days) ───────────────────────
    cutoff = datetime.utcnow() - timedelta(days=30)
    daily = db.session.query(
        func.date(AttackPrediction.timestamp).label('day'),
        func.count(AttackPrediction.id).label('count')
    ).filter(
        AttackPrediction.timestamp >= cutoff,
        AttackPrediction.attack_type != 'Normal'
    ).group_by(func.date(AttackPrediction.timestamp))\
     .order_by(func.date(AttackPrediction.timestamp)).all()

    # ── Attack type distribution ─────────────────────────────
    type_dist = db.session.query(
        AttackPrediction.attack_type,
        func.count(AttackPrediction.id).label('count')
    ).group_by(AttackPrediction.attack_type)\
     .order_by(func.count(AttackPrediction.id).desc()).all()

    # ── Top attacker IPs ─────────────────────────────────────
    top_ips = db.session.query(
        AttackPrediction.source_ip,
        func.count(AttackPrediction.id).label('count'),
        func.max(AttackPrediction.risk_score).label('max_risk')
    ).filter(
        AttackPrediction.attack_type != 'Normal'
    ).group_by(AttackPrediction.source_ip)\
     .order_by(func.count(AttackPrediction.id).desc()).limit(10).all()

    # ── Risk level distribution ──────────────────────────────
    risk_dist = db.session.query(
        AttackPrediction.risk_level,
        func.count(AttackPrediction.id).label('count')
    ).group_by(AttackPrediction.risk_level).all()

    # ── Protocol distribution ────────────────────────────────
    proto_dist = db.session.query(
        NetworkLog.protocol,
        func.count(NetworkLog.id).label('count')
    ).group_by(NetworkLog.protocol).all()

    # ── Geo distribution ─────────────────────────────────────
    geo_dist = db.session.query(
        NetworkLog.country,
        func.count(NetworkLog.id).label('count'),
        NetworkLog.latitude,
        NetworkLog.longitude
    ).filter(
        NetworkLog.country != 'Unknown'
    ).group_by(NetworkLog.country)\
     .order_by(func.count(NetworkLog.id).desc()).limit(15).all()

    # ── Hourly attack pattern ────────────────────────────────
    hourly = db.session.query(
        func.strftime('%H', AttackPrediction.timestamp).label('hour'),
        func.count(AttackPrediction.id).label('count')
    ).filter(
        AttackPrediction.attack_type != 'Normal'
    ).group_by(func.strftime('%H', AttackPrediction.timestamp))\
     .order_by(func.strftime('%H', AttackPrediction.timestamp)).all()

    # ── Threat forecast (next 7 days) ────────────────────────
    forecast = _generate_forecast(daily)

    return jsonify({
        'attacks_per_day': [
            {'date': str(d), 'count': c} for d, c in daily
        ],
        'attack_type_distribution': [
            {'type': t, 'count': c} for t, c in type_dist
        ],
        'top_attacker_ips': [
            {'ip': ip, 'count': cnt, 'max_risk': float(risk or 0)}
            for ip, cnt, risk in top_ips
        ],
        'risk_level_distribution': [
            {'level': l, 'count': c} for l, c in risk_dist
        ],
        'protocol_distribution': [
            {'protocol': p, 'count': c} for p, c in proto_dist
        ],
        'geo_distribution': [
            {'country': co, 'count': c, 'lat': float(lat or 0), 'lng': float(lng or 0)}
            for co, c, lat, lng in geo_dist
        ],
        'hourly_pattern': [
            {'hour': int(h), 'count': c} for h, c in hourly
        ],
        'threat_forecast': forecast
    }), 200


@analytics_bp.route('/analytics/chart/<chart_type>', methods=['GET'])
@jwt_required()
def generate_chart(chart_type):
    """
    GET /api/analytics/chart/{type}
    Generates a matplotlib chart and returns it as PNG.
    chart_type: attacks_per_day | attack_types | risk_levels | top_ips
    """
    try:
        img_bytes = _generate_chart(chart_type)
        return send_file(
            io.BytesIO(img_bytes),
            mimetype='image/png',
            as_attachment=False
        )
    except Exception as e:
        logger.error(f"Chart generation error: {e}")
        return jsonify({'error': str(e)}), 500


def _generate_chart(chart_type: str) -> bytes:
    """Generate matplotlib chart and return as PNG bytes."""
    import matplotlib
    matplotlib.use('Agg')   # Non-interactive backend
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import seaborn as sns
    import pandas as pd
    import numpy as np
    from models import AttackPrediction, NetworkLog
    from app import db
    from sqlalchemy import func
    from datetime import datetime, timedelta
    import io

    # Dark theme
    plt.style.use('dark_background')
    COLORS = ['#00f5ff', '#ff2d55', '#ff6b35', '#ffd60a', '#30d158', '#bf5af2', '#64d2ff', '#ff9f0a']

    fig, ax = plt.subplots(figsize=(10, 5), facecolor='#0d1117')
    ax.set_facecolor('#0d1117')

    if chart_type == 'attacks_per_day':
        cutoff = datetime.utcnow() - timedelta(days=14)
        data = db.session.query(
            func.date(AttackPrediction.timestamp).label('day'),
            func.count(AttackPrediction.id).label('count')
        ).filter(
            AttackPrediction.timestamp >= cutoff,
            AttackPrediction.attack_type != 'Normal'
        ).group_by(func.date(AttackPrediction.timestamp))\
         .order_by(func.date(AttackPrediction.timestamp)).all()

        dates = [str(d) for d, c in data]
        counts = [c for d, c in data]

        ax.plot(dates, counts, color='#00f5ff', linewidth=2.5, marker='o', markersize=6)
        ax.fill_between(dates, counts, alpha=0.2, color='#00f5ff')
        ax.set_title('Attacks Per Day (Last 14 Days)', color='white', fontsize=14, pad=15)
        ax.set_xlabel('Date', color='#8e8e93')
        ax.set_ylabel('Attack Count', color='#8e8e93')
        plt.xticks(rotation=45, ha='right', color='#8e8e93', fontsize=8)
        plt.yticks(color='#8e8e93')

    elif chart_type == 'attack_types':
        data = db.session.query(
            AttackPrediction.attack_type,
            func.count(AttackPrediction.id).label('count')
        ).group_by(AttackPrediction.attack_type)\
         .order_by(func.count(AttackPrediction.id).desc()).all()

        types = [t for t, c in data]
        counts = [c for t, c in data]

        bars = ax.bar(types, counts, color=COLORS[:len(types)], edgecolor='none', width=0.6)
        ax.set_title('Attack Type Distribution', color='white', fontsize=14, pad=15)
        ax.set_xlabel('Attack Type', color='#8e8e93')
        ax.set_ylabel('Count', color='#8e8e93')
        plt.xticks(rotation=30, ha='right', color='#8e8e93')
        plt.yticks(color='#8e8e93')

        for bar, count in zip(bars, counts):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                    str(count), ha='center', va='bottom', color='white', fontsize=9)

    elif chart_type == 'risk_levels':
        data = db.session.query(
            AttackPrediction.risk_level,
            func.count(AttackPrediction.id).label('count')
        ).group_by(AttackPrediction.risk_level).all()

        labels = [l for l, c in data]
        sizes = [c for l, c in data]
        color_map = {'LOW': '#30d158', 'MEDIUM': '#ffd60a', 'HIGH': '#ff6b35', 'CRITICAL': '#ff2d55'}
        colors = [color_map.get(l, '#8e8e93') for l in labels]

        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=colors,
            autopct='%1.1f%%', startangle=90,
            textprops={'color': 'white', 'fontsize': 11},
            wedgeprops={'edgecolor': '#0d1117', 'linewidth': 2}
        )
        for autotext in autotexts:
            autotext.set_fontsize(9)
        ax.set_title('Risk Level Distribution', color='white', fontsize=14, pad=15)

    elif chart_type == 'top_ips':
        data = db.session.query(
            AttackPrediction.source_ip,
            func.count(AttackPrediction.id).label('count')
        ).filter(
            AttackPrediction.attack_type != 'Normal'
        ).group_by(AttackPrediction.source_ip)\
         .order_by(func.count(AttackPrediction.id).desc()).limit(10).all()

        ips = [ip for ip, c in data]
        counts = [c for ip, c in data]

        bars = ax.barh(ips, counts, color='#ff2d55', edgecolor='none')
        ax.set_title('Top 10 Attacker IPs', color='white', fontsize=14, pad=15)
        ax.set_xlabel('Attack Count', color='#8e8e93')
        plt.yticks(color='#8e8e93', fontsize=9)
        plt.xticks(color='#8e8e93')

        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2,
                    str(count), ha='left', va='center', color='white', fontsize=9)

    ax.spines['bottom'].set_color('#2d2d2f')
    ax.spines['left'].set_color('#2d2d2f')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.tick_params(colors='#8e8e93')

    plt.tight_layout()

    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=120, bbox_inches='tight', facecolor='#0d1117')
    plt.close(fig)
    buf.seek(0)
    return buf.read()


def _generate_forecast(daily_data: list) -> list:
    """
    Simple time-based threat forecast for next 7 days.
    Uses moving average + noise as a naive predictor.
    """
    import random
    from datetime import date, timedelta

    counts = [c for d, c in daily_data[-7:]] if daily_data else [5, 8, 6, 9, 7, 11, 8]
    avg = sum(counts) / len(counts) if counts else 7
    attack_types = ['DoS', 'DDoS', 'Probe', 'BruteForce', 'PortScan', 'R2L']

    forecast = []
    today = date.today()
    for i in range(1, 8):
        trend = avg * (1 + random.uniform(-0.3, 0.4))
        forecast.append({
            'date': (today + timedelta(days=i)).isoformat(),
            'predicted_count': max(1, int(round(trend))),
            'predicted_type': random.choice(attack_types),
            'confidence': round(random.uniform(0.60, 0.85), 2)
        })

    return forecast
