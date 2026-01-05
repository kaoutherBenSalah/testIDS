from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import User, get_or_create_users, get_user_by_username, verify_password, load_users_db
from routes.attacks import attacks_bp
from routes.api import api_bp
from routes.ids import ids_bp
from utils.network_utils import get_local_ip, get_gateway_ip

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['SESSION_TYPE'] = 'filesystem'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.register_blueprint(attacks_bp, url_prefix='/api/attack')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(ids_bp, url_prefix='/api')

get_or_create_users()

@login_manager.user_loader
def load_user(username):
    return get_user_by_username(username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if verify_password(username, password):
            user_record = load_users_db().get(username)
            session['user_id'] = username
            session['user_role'] = user_record['role']
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_role = session.get('user_role')
    
    if user_role == 'ATTACKER':
        return redirect(url_for('attacker_dashboard'))
    elif user_role == 'DEFENDER':
        return redirect(url_for('defender_dashboard'))
    else:
        return redirect(url_for('attacker_dashboard'))

@app.route('/attacker')
def attacker_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'ATTACKER':
        return redirect(url_for('login'))
    
    return render_template(
        'attacker.html',
        username=session.get('user_id'),
        local_ip=get_local_ip(),
        gateway_ip=get_gateway_ip()
    )

@app.route('/defender')
def defender_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'DEFENDER':
        return redirect(url_for('login'))
    
    return render_template(
        'defender.html',
        username=session.get('user_id')
    )

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Access denied'}), 403

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500

@app.context_processor
def inject_user():
    return {
        'user_id': session.get('user_id'),
        'user_role': session.get('user_role')
    }

if __name__ == '__main__':
    os.makedirs('logs', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    from modules.firewall_blocker import FirewallBlocker
    import models
    models.firewall_blocker = FirewallBlocker()
    
    print("=" * 60)
    print("🔐 IDS - Flask Version")
    print("=" * 60)
    print(f"📍 Local IP: {get_local_ip()}")
    print(f"🔌 Gateway: {get_gateway_ip()}")
    print()
    print("👤 Default Users:")
    print("   - attacker / attack123 (ATTACKER)")
    print("   - defender / defend123 (DEFENDER)")
    print()
    print("🚀 Running on: http://localhost:5000")
    print("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
