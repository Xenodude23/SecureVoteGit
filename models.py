from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    college_id = db.Column(db.String(50), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='voter')
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    vote_count = db.Column(db.Integer, default=0)

class VoteLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vote_hash = db.Column(db.String(64), unique=True, nullable=False)
    receipt_code = db.Column(db.String(8), nullable=False) # For the Voter Receipt feature

# NEW: Security Feature #10 - Audit Trail
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(50), nullable=False) # e.g., "LOGIN_SUCCESS", "VOTE_CAST"
    details = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))