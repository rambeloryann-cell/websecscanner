from app import db
from datetime import datetime


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('Scan', backref='user', lazy=True, cascade='all, delete-orphan')


class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    url = db.Column(db.Text, nullable=False)
    mode = db.Column(db.String(10), nullable=False)
    score = db.Column(db.Integer)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.relationship('ScanResult', backref='scan', lazy=True, cascade='all, delete-orphan')


class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False)
    category = db.Column(db.String(50))
    check_name = db.Column(db.String(100))
    check_mode = db.Column(db.String(10))
    status = db.Column(db.String(20))
    severity = db.Column(db.String(20))
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)


class FailedLogin(db.Model):
    __tablename__ = 'failed_logins'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45))
    attempted_at = db.Column(db.DateTime, default=datetime.utcnow)
