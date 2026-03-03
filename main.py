from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, set_access_cookies,
    get_jwt_identity, jwt_required, unset_jwt_cookies
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import hashlib
import os
import bleach
from models import db, User, Candidate, VoteLog, AuditLog
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Config
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False  # Set True in production (HTTPS)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
# CRITICAL FIX: Allow CSRF token to be read from Form Data
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Initialize Extensions
db.init_app(app)
jwt = JWTManager(app)

# Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# --- CUSTOM DECORATORS ---

# RBAC Decorator
def role_required(role_name):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(int(user_id))
            if user and user.role == role_name:
                return fn(*args, **kwargs)
            return "Access Denied: Insufficient Permissions", 403

        return decorator

    return wrapper


# --- HELPER FUNCTIONS ---

def sanitize_input(data):
    if isinstance(data, str):
        return bleach.clean(data, strip=True)
    return data


def log_action(action, details, user_id=None):
    log = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=get_remote_address()
    )
    db.session.add(log)
    db.session.commit()


# --- CONTEXT PROCESSOR ---
@app.context_processor
def inject_csrf_token():
    from flask import request
    csrf_token = request.cookies.get('csrf_access_token')
    return dict(csrf_token=csrf_token)


# --- ROUTES ---

# 1. Login
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            # FIX: Convert user.id to string for JWT
            access_token = create_access_token(identity=str(user.id))
            response = make_response(redirect(url_for('vote_page' if user.role == 'voter' else 'admin_dashboard')))
            set_access_cookies(response, access_token)

            log_action("LOGIN_SUCCESS", f"User {username} logged in.", user.id)
            return response
        else:
            log_action("LOGIN_FAILED", f"Failed login attempt for {username}.")
            flash('Invalid username or password')

    return render_template('login.html')


# 2. Sign Up
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        college_id = sanitize_input(request.form.get('college_id'))
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.')
            return redirect(url_for('signup'))

        if User.query.filter_by(college_id=college_id).first():
            flash('This College ID is already registered.')
            return redirect(url_for('signup'))

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        new_user = User(username=username, college_id=college_id, password_hash=hashed_pw, role='voter')

        db.session.add(new_user)
        db.session.commit()
        log_action("USER_REGISTERED", f"New user: {username}", new_user.id)

        flash('Account created! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html')


# 3. Admin Dashboard
@app.route('/admin')
@jwt_required()
@role_required('admin')
def admin_dashboard():
    candidates = Candidate.query.all()
    return render_template('admin_dashboard.html', candidates=candidates)


# 4. Add Candidate
@app.route('/add_candidate', methods=['POST'])
@jwt_required()
@role_required('admin')
def add_candidate():
    name = sanitize_input(request.form.get('name'))
    if name:
        new_candidate = Candidate(name=name)
        db.session.add(new_candidate)
        db.session.commit()
        log_action("CANDIDATE_ADDED", f"Candidate: {name}", int(get_jwt_identity()))
    return redirect(url_for('admin_dashboard'))


# 5. Voting Page (Time Lock Removed)
@app.route('/vote', methods=['GET', 'POST'])
@jwt_required()
def vote_page():
    # FIX: Convert identity to int
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))

    candidates = Candidate.query.all()

    if request.method == 'POST':
        if user.has_voted:
            log_action("VOTE_FRAUD_ATTEMPT", f"User {user.username} tried to vote again.", user_id)
            flash('Fraud attempt detected. You have already voted.')
            return redirect(url_for('vote_page'))

        candidate_id = request.form.get('candidate_id')

        if not candidate_id:
            flash("Please select a candidate.")
            return redirect(url_for('vote_page'))

        try:
            candidate = Candidate.query.get(candidate_id)

            if candidate:
                candidate.vote_count += 1

                import random, string
                receipt_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

                raw_data = f"{candidate.id}-{datetime.now()}-{os.urandom(16)}"
                vote_hash = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()

                new_log = VoteLog(
                    candidate_id=candidate.id,
                    vote_hash=vote_hash,
                    receipt_code=receipt_code
                )
                db.session.add(new_log)

                user.has_voted = True
                db.session.commit()

                log_action("VOTE_CAST", f"Vote recorded. Receipt: {receipt_code}", user_id)

                # FIX: Added 'user=user' to this return statement
                return render_template('vote.html',
                                       candidates=candidates,
                                       has_voted=True,
                                       receipt=receipt_code,
                                       selected_candidate_name=candidate.name,
                                       user=user
                                       )
            else:
                flash("Invalid candidate selected.")

        except Exception as e:
            db.session.rollback()
            log_action("SYSTEM_ERROR", str(e), user_id)
            return f"An error occurred: {e}"

    return render_template('vote.html', candidates=candidates, has_voted=user.has_voted, user=user)


# 6. Results
@app.route('/results')
@jwt_required()
def results_page():
    candidates = Candidate.query.all()
    total_votes = sum(c.vote_count for c in candidates)
    return render_template('results.html', candidates=candidates, total_votes=total_votes)


# 7. Logout
@app.route('/logout')
@jwt_required()
def logout():
    user_id = int(get_jwt_identity())
    log_action("LOGOUT", "User logged out.", user_id)
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response


# --- INITIALIZATION ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username='admin').first():
            hashed_pw = bcrypt.hashpw('admin123'.encode('utf-8'), bcrypt.gensalt())
            admin = User(username='admin', password_hash=hashed_pw, role='admin', college_id='ADMIN001')
            db.session.add(admin)
            db.session.commit()
            print("Admin created: admin / admin123")

        if Candidate.query.count() == 0:
            names = ["Jabez Benny I", "K.Abishek", "Santosh Muthukumar", "Sakthi Sabreesh"]
            for name in names:
                c = Candidate(name=name, vote_count=0)
                db.session.add(c)
            db.session.commit()
            print("Candidates added.")

    app.run(debug=True)