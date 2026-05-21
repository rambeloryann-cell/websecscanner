from flask import Blueprint, jsonify, session
from app.auth.routes import login_required
from app.models import Scan, ScanResult
from app import db

dashboard_bp = Blueprint('dashboard_bp', __name__)


@dashboard_bp.route('/scans', methods=['GET'])
@login_required
def get_scans():
    scans = Scan.query.filter_by(user_id=session['user_id']).order_by(Scan.created_at.desc()).all()
    result = []
    for s in scans:
        crits = sum(1 for r in s.results if r.severity == 'critical' and r.status == 'fail')
        result.append({
            'id': s.id,
            'url': s.url,
            'mode': s.mode,
            'score': s.score,
            'status': s.status,
            'critical_count': crits,
            'created_at': s.created_at.isoformat()
        })
    return jsonify(result), 200


@dashboard_bp.route('/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan introuvable'}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan supprimé'}), 200


@dashboard_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    scans = Scan.query.filter_by(user_id=session['user_id'], status='done').all()
    if not scans:
        return jsonify({'total': 0, 'avg_score': None, 'critical_total': 0, 'last_scan': None}), 200

    scores = [s.score for s in scans if s.score is not None]
    avg_score = round(sum(scores) / len(scores)) if scores else None
    critical_total = sum(
        sum(1 for r in s.results if r.severity == 'critical' and r.status == 'fail')
        for s in scans
    )
    last = max(scans, key=lambda s: s.created_at)
    return jsonify({
        'total': len(scans),
        'avg_score': avg_score,
        'critical_total': critical_total,
        'last_scan': {'url': last.url, 'created_at': last.created_at.isoformat()}
    }), 200
