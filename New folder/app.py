from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import re
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Initialize database
def init_db():
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Login logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    # Create admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        admin_password = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                      ('admin', 'admin@example.com', admin_password, 'admin'))

    conn.commit()
    conn.close()

# Phishing detection model
class PhishingDetector:
    def __init__(self):
        self.model = None
        self.load_model()

    def extract_features(self, url):
        features = {}

        # URL length
        features['url_length'] = len(url)
        features['dots_count'] = url.count('.')
        features['hyphens_count'] = url.count('-')
        features['underscores_count'] = url.count('_')
        features['slashes_count'] = url.count('/')
        features['question_marks'] = url.count('?')
        features['equal_signs'] = url.count('=')
        features['at_signs'] = url.count('@')
        features['and_signs'] = url.count('&')
        features['has_https'] = 1 if url.startswith('https://') else 0

        # IP address check
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        features['has_ip'] = 1 if re.search(ip_pattern, url) else 0

        # Suspicious keywords
        suspicious_keywords = ['secure', 'account', 'update', 'confirm', 'verify', 'login', 'signin', 'bank', 'paypal']
        features['suspicious_keywords'] = sum(1 for keyword in suspicious_keywords if keyword.lower() in url.lower())

        return features

    def load_model(self):
        self.model = LogisticRegression()

        # Sample training data
        sample_urls = [
            'http://paypal-verification.suspicious-site.com/login',
            'https://amazon-security.fake-domain.net/account', 
            'http://microsoft-update.malicious.org/signin',
            'https://www.google.com',
            'https://www.github.com',
            'https://www.stackoverflow.com'
        ]

        sample_labels = [1, 1, 1, 0, 0, 0]  # 1 for phishing, 0 for legitimate

        X_features = []
        for url in sample_urls:
            features = self.extract_features(url)
            X_features.append(list(features.values()))

        X_features = np.array(X_features)
        self.model.fit(X_features, sample_labels)

    def predict(self, url):
        try:
            features = self.extract_features(url)
            X = np.array([list(features.values())])
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0]

            return {
                'is_phishing': bool(prediction),
                'confidence': max(probability) * 100,
                'features': features
            }
        except Exception as e:
            return {
                'is_phishing': False,
                'confidence': 0,
                'error': str(e)
            }

# Initialize phishing detector
phishing_detector = PhishingDetector()

def log_action(user_id, action):
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_logs (user_id, action) VALUES (?, ?)", (user_id, action))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('register.html')

        try:
            conn = sqlite3.connect('website.db')
            cursor = conn.cursor()

            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                          (username, email, hashed_password))
            conn.commit()
            conn.close()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('index'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password, role FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[3]

        log_action(user[0], 'login')

        if user[3] == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        flash('Invalid username or password!', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
    return render_template('admin_dashboard.html')

@app.route('/detect_phishing', methods=['POST'])
def detect_phishing():
    if 'user_id' not in session:
        return jsonify({'error': 'Please login first'})

    url = request.json.get('url', '')
    if not url:
        return jsonify({'error': 'URL is required'})

    result = phishing_detector.predict(url)
    return jsonify(result)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        try:
            conn = sqlite3.connect('website.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET username=?, email=? WHERE id=?",
                          (username, email, session['user_id']))
            conn.commit()
            conn.close()

            session['username'] = username
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('dashboard'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists!', 'error')

    # Get current user data
    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users WHERE id=?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    return render_template('edit_profile.html', user=user)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))

    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users WHERE role != 'admin'")
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['POST'])
def admin_edit_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'})

    data = request.json
    username = data.get('username')
    email = data.get('email')
    role = data.get('role')

    try:
        conn = sqlite3.connect('website.db')
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET username=?, email=?, role=? WHERE id=?",
                      (username, email, role, user_id))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'User updated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'})

    try:
        conn = sqlite3.connect('website.db')
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/admin/login_stats')
def admin_login_stats():
    if 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'})

    conn = sqlite3.connect('website.db')
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            COUNT(CASE WHEN action = 'login' THEN 1 END) as total_logins,
            COUNT(CASE WHEN action = 'logout' THEN 1 END) as total_logouts,
            COUNT(DISTINCT user_id) as unique_users
        FROM login_logs
    """)
    stats = cursor.fetchone()
    conn.close()

    return jsonify({
        'total_logins': stats[0] or 0,
        'total_logouts': stats[1] or 0,
        'unique_users': stats[2] or 0
    })

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'logout')
        session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
