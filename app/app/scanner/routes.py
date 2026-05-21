from flask import Blueprint, request, jsonify, session
from app.auth.routes import login_required
from app.models import Scan, ScanResult
from app import db
from app.scanner.passive import run_passive_scan
from app.scanner.active import run_active_scan
from app.scanner.report import calculate_score
import os
import ipaddress
from urllib.parse import urlparse

scanner_bp = Blueprint('scanner_bp', __name__)


def is_allowed(url):
    allowed_raw = os.environ.get('ALLOWED_TARGETS', '')
    if not allowed_raw:
        return False
    allowed = [t.strip() for t in allowed_raw.split(',') if t.strip()]
    parsed = urlparse(url)
    host = parsed.hostname or url.strip()
    for entry in allowed:
        if host == entry:
            return True
        if host.endswith('.' + entry):
            return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False


@scanner_bp.route('/start', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Données manquantes'}), 400

    url = data.get('url', '').strip()
    mode = data.get('mode', 'passive')

    if not url:
        return jsonify({'error': 'URL requise'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    if mode not in ('passive', 'active'):
        return jsonify({'error': 'Mode invalide'}), 400
    if mode == 'active' and not is_allowed(url):
        return jsonify({'error': 'Cible non autorisée pour le scan actif. Ajouter le domaine dans ALLOWED_TARGETS.'}), 403

    scan = Scan(user_id=session['user_id'], url=url, mode=mode, status='running')
    db.session.add(scan)
    db.session.commit()

    try:
        results = run_passive_scan(url)
        if mode == 'active':
            results += run_active_scan(url)

        score = calculate_score(results)

        for r in results:
            db.session.add(ScanResult(
                scan_id=scan.id,
                category=r['category'],
                check_name=r['check_name'],
                check_mode=r['check_mode'],
                status=r['status'],
                severity=r['severity'],
                description=r['description'],
                recommendation=r['recommendation']
            ))

        scan.score = score
        scan.status = 'done'
        db.session.commit()

    except Exception as e:
        scan.status = 'error'
        db.session.commit()
        return jsonify({'error': f'Erreur durant le scan : {str(e)}'}), 500

    return jsonify({'scan_id': scan.id, 'score': score, 'status': 'done'}), 200


@scanner_bp.route('/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan introuvable'}), 404
    return jsonify({
        'id': scan.id, 'url': scan.url, 'mode': scan.mode,
        'score': scan.score, 'status': scan.status,
        'created_at': scan.created_at.isoformat()
    }), 200


@scanner_bp.route('/<int:scan_id>/report', methods=['GET'])
@login_required
def get_report(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first()
    if not scan:
        return jsonify({'error': 'Scan introuvable'}), 404
    results = ScanResult.query.filter_by(scan_id=scan_id).all()
    return jsonify({
        'scan': {
            'id': scan.id, 'url': scan.url, 'mode': scan.mode,
            'score': scan.score, 'status': scan.status,
            'created_at': scan.created_at.isoformat()
        },
        'results': [{
            'category': r.category,
            'check_name': r.check_name,
            'check_mode': r.check_mode,
            'status': r.status,
            'severity': r.severity,
            'description': r.description,
            'recommendation': r.recommendation
        } for r in results]
    }), 200
