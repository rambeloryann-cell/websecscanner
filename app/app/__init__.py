from flask import Flask, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from dotenv import load_dotenv
import os

load_dotenv()

db = SQLAlchemy()
sess = Session()
limiter = Limiter(key_func=get_remote_address, default_limits=[])
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-me')
    app.config['SQLALCHEMY_DATABASE_URI'] = (
        f"mysql+pymysql://{os.environ.get('MYSQL_USER', 'websec')}:"
        f"{os.environ.get('MYSQL_PASSWORD', 'websec')}@"
        f"{os.environ.get('MYSQL_HOST', 'db')}:"
        f"{os.environ.get('MYSQL_PORT', '3306')}/"
        f"{os.environ.get('MYSQL_DATABASE', 'websecscanner')}"
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SESSION_TYPE'] = 'sqlalchemy'
    app.config['SESSION_SQLALCHEMY'] = db
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # CSRF géré manuellement sur les API JSON

    # Extensions
    db.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        # Import modèles
        from app.models import User, Scan, ScanResult, FailedLogin

        # Init session après db
        app.config['SESSION_SQLALCHEMY'] = db
        sess.init_app(app)

        # Créer les tables
        db.create_all()

        # Blueprints
        from app.auth.routes import auth_bp
        from app.scanner.routes import scanner_bp
        from app.dashboard.routes import dashboard_bp

        app.register_blueprint(auth_bp, url_prefix='/api/auth')
        app.register_blueprint(scanner_bp, url_prefix='/api/scan')
        app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')

    # Routes HTML — en dehors du with pour éviter les conflits
    from app.auth.routes import login_required

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard_page'))
        return redirect(url_for('login_page'))

    @app.route('/login')
    def login_page():
        if 'user_id' in session:
            return redirect(url_for('dashboard_page'))
        return render_template('login.html')

    @app.route('/register')
    def register_page():
        if 'user_id' in session:
            return redirect(url_for('dashboard_page'))
        return render_template('register.html')

    @app.route('/dashboard')
    @login_required
    def dashboard_page():
        return render_template('dashboard.html')

    @app.route('/scan')
    @login_required
    def scan_page():
        return render_template('scan.html')

    @app.route('/report/<int:scan_id>')
    @login_required
    def report_page(scan_id):
        return render_template('report.html', scan_id=scan_id)

    return app
