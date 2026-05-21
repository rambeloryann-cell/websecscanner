from flask import Blueprint, request, jsonify, session
from functools import wraps
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerifyMismatchError
from app import db, limiter
from app.models import User, FailedLogin

auth_bp = Blueprint('auth_bp', __name__)
ph = PasswordHasher()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            from flask import redirect, url_for
            # Si c'est une requête API, retourner JSON
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Non authentifié'}), 401
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Données manquantes'}), 400

    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Tous les champs sont requis'}), 400
    if len(username) < 3:
        return jsonify({'error': 'Nom d\'utilisateur trop court (3 caractères minimum)'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Mot de passe trop court (8 caractères minimum)'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email déjà utilisé'}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Nom d\'utilisateur déjà pris'}), 409

    user = User(username=username, email=email, password_hash=ph.hash(password))
    db.session.add(user)
    db.session.commit()

    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({'message': 'Compte créé', 'username': user.username}), 201


@auth_bp.route('/login', methods=['POST'])
@limiter.limit('10 per minute')
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'Données manquantes'}), 400

    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email et mot de passe requis'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        _log_failed(request.remote_addr)
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    try:
        ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        _log_failed(request.remote_addr)
        return jsonify({'error': 'Email ou mot de passe incorrect'}), 401

    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(password)
        db.session.commit()

    session.clear()
    session['user_id'] = user.id
    session['username'] = user.username
    return jsonify({'message': 'Connecté', 'username': user.username}), 200


@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Déconnecté'}), 200


@auth_bp.route('/me', methods=['GET'])
@login_required
def me():
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return jsonify({'error': 'Utilisateur introuvable'}), 404
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'created_at': user.created_at.isoformat()
    }), 200


def _log_failed(ip):
    try:
        db.session.add(FailedLogin(ip_address=ip))
        db.session.commit()
    except Exception:
        db.session.rollback()
