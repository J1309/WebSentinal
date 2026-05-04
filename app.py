from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
import threading
import time
import requests
import os
import json
import queue
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import text
import subprocess
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def load_dotenv(path: str = ".env") -> None:
    try:
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            for raw in f.readlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if not key:
                    continue
                if key not in os.environ or not str(os.environ.get(key, "")).strip():
                    os.environ[key] = value
    except Exception:
        return

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# Use /data for persistent storage on Hugging Face Spaces
data_dir = os.environ.get('HF_HOME', '/data')
if not os.path.exists(data_dir):
    data_dir = '.'
db_path = os.path.join(data_dir, 'vulnscan.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

db = SQLAlchemy(app)

scan_events = {}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_url = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    error_message = db.Column(db.Text)
    total_vulnerabilities = db.Column(db.Integer, default=0)
    high_risk = db.Column(db.Integer, default=0)
    medium_risk = db.Column(db.Integer, default=0)
    low_risk = db.Column(db.Integer, default=0)
    informational = db.Column(db.Integer, default=0)
    progress = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'target_url': self.target_url,
            'status': self.status,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'total_vulnerabilities': self.total_vulnerabilities,
            'high_risk': self.high_risk,
            'medium_risk': self.medium_risk,
            'low_risk': self.low_risk,
            'informational': self.informational,
            'progress': self.progress,
            'error_message': self.error_message
        }

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey('scan.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)
    url = db.Column(db.String(500))
    parameter = db.Column(db.String(200))
    description = db.Column(db.Text)
    solution = db.Column(db.Text)
    evidence = db.Column(db.Text)
    severity = db.Column(db.String(20), default='unknown')
    matched_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'risk_level': self.risk_level,
            'url': self.url,
            'parameter': self.parameter,
            'description': self.description,
            'solution': self.solution,
            'evidence': self.evidence,
            'severity': self.severity,
            'matched_at': self.matched_at.isoformat() if self.matched_at else None
        }

with app.app_context():
    db.create_all()
    if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite'):
        try:
            vuln_rows = db.session.execute(text("PRAGMA table_info(vulnerability)")).fetchall()
            vuln_cols = {row[1] for row in vuln_rows}
            if "severity" not in vuln_cols:
                db.session.execute(text("ALTER TABLE vulnerability ADD COLUMN severity TEXT DEFAULT 'unknown'"))
                db.session.commit()
        except Exception:
            db.session.rollback()

def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            wants_json = (
                request.accept_mimetypes.best == 'application/json'
                or request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            )
            if wants_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapper

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        if not user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('new_scan'))
        return view_func(*args, **kwargs)
    return wrapper

def validate_url(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False, "Invalid URL format"
        return True, "URL format is valid"
    except Exception as e:
        return False, f"Invalid URL: {str(e)}"

def ensure_scan_error_message_column():
    try:
        col_rows = db.session.execute(text("PRAGMA table_info(scan)")).fetchall()
        existing_cols = {row[1] for row in col_rows}
        if "error_message" not in existing_cols:
            db.session.execute(text("ALTER TABLE scan ADD COLUMN error_message TEXT"))
            db.session.commit()
    except Exception:
        db.session.rollback()

def run_scan(scan_id, target_url):
    if scan_id not in scan_events:
        scan_events[scan_id] = queue.Queue()

    q = scan_events[scan_id]

    def emit(event_type, data):
        q.put({'type': event_type, 'data': data})

    def add_vulnerability(name, risk_level, url, description, solution, evidence):
        nonlocal high_count, medium_count, low_count, info_count, total_found
        vuln = Vulnerability(
            scan_id=scan_id,
            name=name,
            risk_level=risk_level,
            url=url,
            description=description,
            solution=solution,
            evidence=evidence
        )
        db.session.add(vuln)
        db.session.commit()

        if risk_level == 'High':
            high_count += 1
        elif risk_level == 'Medium':
            medium_count += 1
        elif risk_level == 'Low':
            low_count += 1
        else:
            info_count += 1
        
        total_found += 1
        scan.total_vulnerabilities = total_found
        scan.high_risk = high_count
        scan.medium_risk = medium_count
        scan.low_risk = low_count
        scan.informational = info_count
        db.session.commit()
        
        emit('finding', vuln.to_dict())
        return vuln

    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = "scanning"
        scan.progress = 5
        db.session.commit()
        emit('status', scan.to_dict())

        high_count, medium_count, low_count, info_count, total_found = 0, 0, 0, 0, 0

        try:
            emit('progress', {'message': 'Fetching target information...', 'progress': 10})
            
            parsed = urlparse(target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            response = requests.get(target_url, timeout=15, verify=False, allow_redirects=True)
            final_url = response.url
            headers = response.headers
            status_code = response.status_code
            content = response.text

            emit('progress', {'message': 'Checking security headers...', 'progress': 25})

            security_checks = [
                ('Strict-Transport-Security', 'High', 'Missing HSTS Header', 'Enable HTTP Strict Transport Security (HSTS) to enforce HTTPS connections.', 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'),
                ('Content-Security-Policy', 'Medium', 'Missing Content Security Policy', 'Enable CSP to prevent XSS and injection attacks.', 'Add header: Content-Security-Policy: default-src \'self\''),
                ('X-Content-Type-Options', 'Medium', 'Missing X-Content-Type-Options', 'Enable to prevent MIME-sniffing attacks.', 'Add header: X-Content-Type-Options: nosniff'),
                ('X-Frame-Options', 'Medium', 'Missing X-Frame-Options', 'Enable to prevent clickjacking attacks.', 'Add header: X-Frame-Options: DENY'),
                ('X-XSS-Protection', 'Low', 'Missing X-XSS-Protection', 'Enable browser XSS filter.', 'Add header: X-XSS-Protection: 1; mode=block'),
                ('Referrer-Policy', 'Low', 'Missing Referrer-Policy', 'Control referrer information sent with requests.', 'Add header: Referrer-Policy: strict-origin-when-cross-origin'),
                ('Permissions-Policy', 'Low', 'Missing Permissions-Policy', 'Control browser features and APIs.', 'Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()'),
            ]

            for header_name, risk, name, desc, sol in security_checks:
                if header_name not in headers:
                    add_vulnerability(
                        name=name,
                        risk_level=risk,
                        url=base_url,
                        description=desc,
                        solution=sol,
                        evidence=f"Header '{header_name}' not found in response headers"
                    )
                    emit('progress', {'message': f'Checking: {name}...', 'progress': 25 + total_found * 3})

            emit('progress', {'message': 'Checking HTTP configuration...', 'progress': 50})

            if status_code == 200:
                add_vulnerability(
                    name='Server Banner Disclosed',
                    risk_level='Low',
                    url=final_url,
                    description=f'Server reveals version information: {headers.get("Server", "Unknown")}',
                    solution='Configure server to hide version banners',
                    evidence=f"Server: {headers.get('Server', 'Not specified')}"
                )

            if 'X-Powered-By' in headers:
                add_vulnerability(
                    name='X-Powered-By Header Exposed',
                    risk_level='Low',
                    url=final_url,
                    description=f'Application reveals technology: {headers.get("X-Powered-By")}',
                    solution='Remove X-Powered-By header from response',
                    evidence=f"X-Powered-By: {headers.get('X-Powered-By')}"
                )

            if parsed.scheme == 'http':
                add_vulnerability(
                    name='Insecure HTTP Protocol',
                    risk_level='High',
                    url=base_url,
                    description='Site uses unencrypted HTTP instead of HTTPS',
                    solution='Enable HTTPS and redirect HTTP to HTTPS',
                    evidence='Connection is not encrypted'
                )

            emit('progress', {'message': 'Checking for sensitive files...', 'progress': 65})

            sensitive_paths = [
                ('/robots.txt', 'Robots File', 'Low', 'Check robots.txt for disallowed paths that may reveal sensitive areas'),
                ('/sitemap.xml', 'Sitemap File', 'Low', 'Sitemap may reveal admin or private areas'),
                ('/.git/config', 'Git Config', 'Medium', 'Exposed .git directory may reveal source code'),
                ('/.svn/entries', 'SVN Config', 'Medium', 'Exposed SVN directory may reveal source code'),
                ('/phpinfo.php', 'PHP Info', 'High', 'phpinfo() may reveal sensitive server configuration'),
                ('/admin/', 'Admin Panel', 'Medium', 'Admin panel may be accessible without authentication'),
                ('/login', 'Login Page', 'Low', 'Login page found - check for brute force vulnerabilities'),
                ('/wp-admin/', 'WordPress Admin', 'High', 'WordPress admin panel exposed'),
                ('/wp-content/', 'WordPress Content', 'Medium', 'WordPress content directory accessible'),
                ('/config.php', 'Config File', 'High', 'Configuration file may contain database credentials'),
                ('/config.json', 'Config File', 'High', 'Configuration file may contain sensitive data'),
                ('/.env', 'Environment File', 'High', 'Environment file may contain API keys and secrets'),
                ('/backup/', 'Backup Directory', 'High', 'Backup directory may contain source code'),
                ('/debug/', 'Debug Mode', 'High', 'Debug mode may expose sensitive information'),
                ('/.aws/credentials', 'AWS Credentials', 'Critical', 'AWS credentials exposed'),
                ('/server-status', 'Apache Status', 'Medium', 'Server status page reveals server information'),
            ]

            for path, name, risk, desc in sensitive_paths:
                if path == '/robots.txt' or path == '/sitemap.xml':
                    try:
                        check_url = base_url + path
                        r = requests.get(check_url, timeout=5, verify=False, allow_redirects=True)
                        if r.status_code == 200:
                            add_vulnerability(
                                name=name,
                                risk_level=risk,
                                url=check_url,
                                description=desc,
                                solution='Ensure sensitive paths are not accessible or are properly protected',
                                evidence=f"Status: {r.status_code}, Length: {len(r.text)}"
                            )
                    except:
                        pass
                else:
                    try:
                        check_url = base_url + path
                        r = requests.head(check_url, timeout=5, verify=False, allow_redirects=True)
                        if r.status_code in (200, 301, 302, 403):
                            add_vulnerability(
                                name=name,
                                risk_level=risk,
                                url=check_url,
                                description=desc,
                                solution='Ensure this path requires authentication or is properly protected',
                                evidence=f"Status: {r.status_code}"
                            )
                    except:
                        pass

            emit('progress', {'message': 'Checking for common vulnerabilities...', 'progress': 80})

            test_payloads = [
                ("'", "SQL Injection", "High", "Unescaped quotes may indicate SQL injection vulnerability"),
                ("' OR '1'='1", "SQL Injection (Auth Bypass)", "High", "Authentication bypass via SQL injection"),
                ("' UNION SELECT NULL--", "SQL Injection (Union)", "High", "Union-based SQL injection possible"),
                ('<script>alert(1)</script>', "XSS Reflection", "High", "Unescaped script tags may indicate XSS vulnerability"),
                ('<img src=x onerror=alert(1)>', "XSS Event Handler", "High", "XSS via image error event"),
                ('<svg/onload=alert(1)>', "XSS SVG", "High", "XSS via SVG loading"),
                ('../../../etc/passwd', "Path Traversal", "High", "Directory traversal may be possible"),
                ('..%2F..%2F..%2Fetc%2Fpasswd', "Path Traversal (Encoded)", "High", "Encoded path traversal attempt"),
                ('{{7*7}}', "Template Injection (Jinja2)", "High", "Template injection possible"),
                ('${7*7}', "Template Injection (Groovy)", "High", "Server-side template injection"),
                ('<%25=7*7%25>', "Template Injection (ASP)", "High", "ASP template injection"),
                ('||cat /etc/passwd||', "Command Injection", "High", "OS command injection possible"),
                ('; ls -la', "Command Injection (Semicolon)", "High", "Command chaining injection"),
                ('eval(atob("YWxlcnQoMSk="))', "JavaScript Injection", "High", "JavaScript code injection"),
                ('<iframe src="javascript:alert(1)">', "XSS Iframe", "High", "XSS via iframe with javascript protocol"),
            ]

            for payload, name, risk, desc in test_payloads:
                try:
                    if '?' in final_url or '=' in final_url:
                        test_url = final_url + ('' if '?' in final_url else '?') + f'test={payload}'
                        r = requests.get(test_url, timeout=5, verify=False)
                        if payload in r.text or 'error' in r.text.lower():
                            add_vulnerability(
                                name=name,
                                risk_level=risk,
                                url=test_url,
                                description=desc,
                                solution='Sanitize and validate all user inputs',
                                evidence=f"Payload: {payload}, Response length: {len(r.text)}"
                            )
                except:
                    pass

            emit('progress', {'message': 'Checking cookies and sessions...', 'progress': 82})
            
            cookies = response.cookies
            if cookies:
                for cookie in cookies:
                    cookie_issues = []
                    if not cookie.secure and parsed.scheme == 'https':
                        cookie_issues.append('Cookie not marked as Secure')
                    if not cookie.has_non_local_characters():
                        cookie_issues.append('Cookie may be vulnerable to XSS')
                    if cookie_issues:
                        add_vulnerability(
                            name='Insecure Cookie Configuration',
                            risk_level='Medium',
                            url=final_url,
                            description=f'Cookie "{cookie.name}" has security issues: {", ".join(cookie_issues)}',
                            solution='Set Secure, HttpOnly, and SameSite attributes on cookies',
                            evidence=f"Cookie: {cookie.name}, Issues: {', '.join(cookie_issues)}"
                        )

            emit('progress', {'message': 'Checking CORS configuration...', 'progress': 84})
            
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*':
                add_vulnerability(
                    name='CORS Wildcard Allow',
                    risk_level='Medium',
                    url=base_url,
                    description='CORS allows any origin (*), allowing cross-site requests from any website',
                    solution='Restrict CORS to specific trusted origins',
                    evidence=f"Access-Control-Allow-Origin: {cors_header}"
                )

            emit('progress', {'message': 'Checking SSL/TLS configuration...', 'progress': 86})
            
            if parsed.scheme == 'https':
                try:
                    ssl_context = requests.get(target_url, timeout=5, verify=True)
                    cert = ssl_context
                    if hasattr(ssl_context, 'cert') and ssl_context.cert:
                        days_remaining = (ssl_context.cert.not_valid_after - datetime.now()).days
                        if days_remaining < 30:
                            add_vulnerability(
                                name='SSL Certificate Expiring',
                                risk_level='Medium',
                                url=base_url,
                                description=f'SSL certificate expires in {days_remaining} days',
                                solution='Renew SSL certificate before expiration',
                                evidence=f"Expires: {ssl_context.cert.not_valid_after}"
                            )
                except:
                    pass

            emit('progress', {'message': 'Detecting web technologies...', 'progress': 88})
            
            server = headers.get('Server', '')
            x_powered = headers.get('X-Powered-By', '')
            if server or x_powered:
                add_vulnerability(
                    name='Technology Stack Disclosure',
                    risk_level='Low',
                    url=base_url,
                    description=f'Technology stack revealed: {server} {x_powered}',
                    solution='Configure server to hide technology information',
                    evidence=f"Server: {server}, X-Powered-By: {x_powered}"
                )

            emit('progress', {'message': 'Checking for HTTP methods...', 'progress': 90})
            
            try:
                methods = requests.options(base_url, timeout=5, verify=False)
                allowed_methods = methods.get('Allow', '')
                dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                for method in dangerous_methods:
                    if method in allowed_methods:
                        add_vulnerability(
                            name=f'Dangerous HTTP Method Allowed',
                            risk_level='Medium',
                            url=base_url,
                            description=f'HTTP method "{method}" is allowed, which may pose security risks',
                            solution='Disable unnecessary HTTP methods',
                            evidence=f"Allowed methods: {allowed_methods}"
                        )
            except:
                pass

            emit('progress', {'message': 'Finalizing scan...', 'progress': 95})

            scan.progress = 100
            scan.status = 'completed'
            scan.end_time = datetime.utcnow()
            db.session.commit()

            emit('status', scan.to_dict())
            emit('complete', {'message': f'Scan completed! Found {total_found} issues.'})

        except requests.exceptions.Timeout:
            scan.status = 'failed'
            scan.progress = 100
            scan.end_time = datetime.utcnow()
            scan.error_message = 'Target URL timed out'
            db.session.commit()
            emit('error', {'message': 'Target URL timed out'})

        except requests.exceptions.ConnectionError:
            scan.status = 'failed'
            scan.progress = 100
            scan.end_time = datetime.utcnow()
            scan.error_message = 'Could not connect to target URL'
            db.session.commit()
            emit('error', {'message': 'Could not connect to target URL'})

        except Exception as e:
            scan.status = 'failed'
            scan.progress = 100
            scan.end_time = datetime.utcnow()
            scan.error_message = str(e)
            db.session.commit()
            emit('error', {'message': str(e)})

        finally:
            q.put(None)

@app.route('/')
def index():
    return render_template('home.html', user=current_user())

@app.route('/scan/new')
@login_required
def new_scan():
    return render_template('index.html', user=current_user())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('new_scan'))

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not email or not password:
            flash('Email and password are required.', 'danger')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return redirect(url_for('register'))

        existing = User.query.filter_by(email=email).first()
        if existing:
            flash('An account with that email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session['user_id'] = user.id
        flash('Account created. You are now logged in.', 'success')
        return redirect(url_for('new_scan'))

    return render_template('register.html', user=current_user())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('new_scan'))

    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        flash('Logged in successfully.', 'success')

        next_url = request.args.get('next')
        if next_url and next_url.startswith('/'):
            return redirect(next_url)
        return redirect(url_for('new_scan'))

    return render_template('login.html', user=current_user())

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    target_url = request.form.get('target_url')
    template = request.form.get('template', 'default')

    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400

    ensure_scan_error_message_column()

    is_valid, message = validate_url(target_url)
    if not is_valid:
        return jsonify({'error': message}), 400

    scan = Scan(target_url=target_url)
    db.session.add(scan)
    db.session.commit()

    scan_events[scan.id] = queue.Queue()
    scan_thread = threading.Thread(target=run_scan, args=(scan.id, target_url))
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({'scan_id': scan.id, 'message': 'Scan started successfully'})

@app.route('/scan/<scan_id>/stream')
@login_required
def scan_stream(scan_id):
    scan = Scan.query.get_or_404(scan_id)

    def generate():
        q = scan_events.get(scan_id, queue.Queue())

        def get_events():
            while True:
                try:
                    event = q.get(timeout=30)
                    if event is None:
                        return
                    yield event
                except queue.Empty:
                    yield {'type': 'ping', 'data': {}}

        for event in get_events():
            if event.get('type') == 'ping':
                yield 'event: ping\ndata: {}\n\n'
            else:
                event_type = event.get('type', 'message')
                event_data = json.dumps(event.get('data', {}))
                yield f'event: {event_type}\ndata: {event_data}\n\n'

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/scan/<scan_id>')
@login_required
def scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).order_by(Vulnerability.matched_at.desc()).all()
    return render_template('scan_results.html', scan=scan, vulnerabilities=vulnerabilities, user=current_user())

@app.route('/scan/<scan_id>/progress')
@login_required
def scan_progress(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())

@app.route('/history')
@login_required
def scan_history():
    scans = Scan.query.order_by(Scan.start_time.desc()).all()
    return render_template('history.html', scans=scans, user=current_user())

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 7860))
    app.run(debug=False, host='0.0.0.0', port=port)
