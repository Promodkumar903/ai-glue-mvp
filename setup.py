import os
import shutil

# ---- Delete old folders (if any) ----
for folder in ['api', 'services', 'templates']:
    if os.path.exists(folder):
        shutil.rmtree(folder)

# ---- Create fresh folders ----
os.makedirs('api', exist_ok=True)
os.makedirs('services', exist_ok=True)
os.makedirs('templates', exist_ok=True)

# ---- Write api/__init__.py ----
with open('api/__init__.py', 'w', encoding='utf-8') as f:
    f.write('')

# ---- Write api/routes.py ----
routes_code = '''
from flask import request, jsonify, render_template
from functools import wraps
from models import User, RequestLog, db
from services.auth_service import decode_token, get_user_by_username, create_user, create_token
from services.policy_service import assess_risk
from services.decision_service import generate_plan
from services.execution_service import run_sandbox
from services.audit_service import log_action
import time
import psutil
from datetime import timedelta

start_time = time.time()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        payload = decode_token(token.split(' ')[1])
        if not payload:
            return jsonify({'error': 'Invalid token'}), 401
        user = User.query.get(int(payload['sub']))
        if not user:
            return jsonify({'error': 'User not found'}), 401
        return f(user, *args, **kwargs)
    return decorated

def register_routes(app):

    @app.route('/')
    def index():
        return render_template('dashboard.html')

    @app.route('/login-page')
    def login_page():
        return render_template('login.html')

    @app.route('/signup', methods=['POST'])
    def signup():
        data = request.json
        user = create_user(data.get('username'), data.get('password'))
        if not user:
            return jsonify({'error': 'User exists'}), 400
        return jsonify({'msg': 'Created'})

    @app.route('/login', methods=['POST'])
    def login():
        data = request.json
        user = get_user_by_username(data.get('username'))
        from services.auth_service import verify_password
        if not user or not verify_password(data.get('password'), user.password_hash):
            return jsonify({'error': 'Invalid'}), 401
        return jsonify({'access_token': create_token(user.id)})

    @app.route('/submit', methods=['POST'])
    @login_required
    def submit(user):
        prompt = request.json.get('prompt')
        if not prompt:
            return jsonify({'error': 'Missing'}), 400
        risk = assess_risk(prompt)
        plan = generate_plan(prompt)
        req = RequestLog(
            user_id=user.id,
            prompt=prompt,
            plan=plan,
            risk_level=risk,
            status='APPROVED',
            confidence=plan['confidence']
        )
        db.session.add(req)
        db.session.commit()
        log_action(user.id, 'SUBMIT', {'req_id': req.id, 'risk': risk})
        return jsonify({'id': req.id, 'status': req.status})

    @app.route('/execute/<int:req_id>', methods=['POST'])
    @login_required
    def execute(user, req_id):
        req = RequestLog.query.get(req_id)
        if not req:
            return jsonify({'error': 'Not found'}), 404
        if req.user_id != user.id and user.role != 'admin':
            return jsonify({'error': 'Forbidden'}), 403
        req.status = 'RUNNING'
        db.session.commit()
        code = req.plan.get('code_snippet', 'print("No Code")')
        output, exec_time = run_sandbox(code)
        req.result = output
        req.status = 'DONE'
        req.execution_time = exec_time
        db.session.commit()
        log_action(user.id, 'EXECUTE', {'req_id': req_id, 'time': exec_time})
        return jsonify({'status': 'DONE', 'result': output})

    @app.route('/requests', methods=['GET'])
    @login_required
    def get_requests(user):
        if user.role == 'admin':
            reqs = RequestLog.query.order_by(RequestLog.id.desc()).all()
        else:
            reqs = RequestLog.query.filter_by(user_id=user.id).order_by(RequestLog.id.desc()).all()
        return jsonify([{
            'id': r.id, 'prompt': r.prompt, 'status': r.status,
            'risk_level': r.risk_level, 'result': r.result
        } for r in reqs])

    @app.route('/api/stats')
    @login_required
    def api_stats(user):
        total_users = User.query.count()
        total_requests = RequestLog.query.count()
        high_risk = RequestLog.query.filter_by(risk_level='HIGH').count()
        done = RequestLog.query.filter_by(status='DONE').count()
        rate = f"{round((done / total_requests * 100) if total_requests > 0 else 0, 1)}%"
        return jsonify({
            'users': total_users,
            'total_requests': total_requests,
            'high_risk': high_risk,
            'success_rate': rate,
            'username': user.username
        })

    @app.route('/api/recent')
    @login_required
    def api_recent(user):
        logs = RequestLog.query.order_by(RequestLog.id.desc()).limit(10).all()
        return jsonify([{
            'id': r.id, 'prompt': r.prompt, 'status': r.status,
            'risk_level': r.risk_level, 'result': r.result
        } for r in logs])

    @app.route('/api/audit')
    @login_required
    def api_audit(user):
        from services.audit_service import get_audit_logs
        logs = get_audit_logs(None if user.role == 'admin' else user.id, 100)
        return jsonify([{
            'user_id': l.user_id, 'action': l.action,
            'details': l.details, 'timestamp': l.timestamp.isoformat()
        } for l in logs])

    @app.route('/api/health')
    @login_required
    def api_health(user):
        uptime = str(timedelta(seconds=int(time.time() - start_time)))
        try:
            cpu = psutil.cpu_percent()
            mem = psutil.virtual_memory().used / (1024*1024)
        except:
            cpu = 0
            mem = 0
        return jsonify({
            'uptime': uptime,
            'cpu': f"{cpu}%",
            'memory': f"{round(mem, 1)} MB",
            'logs': 'All systems operational.'
        })
'''
with open('api/routes.py', 'w', encoding='utf-8') as f:
    f.write(routes_code)

# ---- Write services/__init__.py ----
with open('services/__init__.py', 'w', encoding='utf-8') as f:
    f.write('')

# ---- Write services/auth_service.py ----
auth_code = '''
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from config import Config
from models import User, db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(user_id):
    payload = {
        'sub': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
    except:
        return None

def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

def create_user(username, password):
    if get_user_by_username(username):
        return None
    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user
'''
with open('services/auth_service.py', 'w', encoding='utf-8') as f:
    f.write(auth_code)

# ---- Write services/policy_service.py ----
policy_code = '''
from config import Config

def assess_risk(prompt):
    high = Config.HIGH_RISK_KEYWORDS
    med = Config.MEDIUM_RISK_KEYWORDS
    if any(k in prompt.lower() for k in high):
        return 'HIGH'
    if any(k in prompt.lower() for k in med):
        return 'MEDIUM'
    return 'LOW'
'''
with open('services/policy_service.py', 'w', encoding='utf-8') as f:
    f.write(policy_code)

# ---- Write services/decision_service.py ----
decision_code = '''
def generate_plan(prompt):
    return {
        'steps': ['Analyze Request', 'Generate Code', 'Execute in Sandbox'],
        'code_snippet': f"print('AI Glue Executing: {prompt[:30]}...')\\nprint('Task Completed Successfully!')",
        'confidence': 0.92 if len(prompt) < 50 else 0.78
    }
'''
with open('services/decision_service.py', 'w', encoding='utf-8') as f:
    f.write(decision_code)

# ---- Write services/execution_service.py ----
execution_code = '''
import os
import subprocess
import tempfile
import time
from config import Config

def run_sandbox(code):
    start_time = time.time()
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, 'script.py')
            with open(file_path, 'w') as f:
                f.write(code)
            result = subprocess.run(
                ['python', file_path],
                capture_output=True,
                text=True,
                timeout=Config.SANDBOX_TIMEOUT,
                cwd=tmpdir
            )
            output = result.stdout if result.stdout else result.stderr
            return output, round(time.time() - start_time, 2)
    except subprocess.TimeoutExpired:
        return 'Timeout (5s)', 5.0
    except Exception as e:
        return f'Error: {str(e)}', round(time.time() - start_time, 2)
'''
with open('services/execution_service.py', 'w', encoding='utf-8') as f:
    f.write(execution_code)

# ---- Write services/audit_service.py ----
audit_code = '''
from models import AuditLog, db

def log_action(user_id, action, details=None):
    log = AuditLog(user_id=user_id, action=action, details=details or {})
    db.session.add(log)
    db.session.commit()
    return log

def get_audit_logs(user_id=None, limit=100):
    query = AuditLog.query
    if user_id:
        query = query.filter_by(user_id=user_id)
    return query.order_by(AuditLog.id.desc()).limit(limit).all()
'''
with open('services/audit_service.py', 'w', encoding='utf-8') as f:
    f.write(audit_code)

# ---- Write templates/dashboard.html ----
dashboard_html = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Glue v4.1 - Mission Control</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0b0e14; color: #e6edf3; display: flex; min-height: 100vh; }
        .sidebar { width: 260px; background: #0d1117; border-right: 1px solid #21262d; padding: 24px 16px; height: 100vh; position: sticky; top: 0; overflow-y: auto; }
        .logo { font-size: 22px; font-weight: 700; color: #58a6ff; margin-bottom: 32px; }
        .logo span { color: #f0883e; }
        .nav-item { display: flex; align-items: center; padding: 10px 14px; border-radius: 8px; color: #8b949e; text-decoration: none; margin-bottom: 4px; cursor: pointer; transition: 0.2s; }
        .nav-item:hover, .nav-item.active { background: #1c2333; color: #f0f6fc; }
        .nav-item .icon { margin-right: 12px; font-size: 18px; width: 24px; text-align: center; }
        .logout { margin-top: 40px; border-top: 1px solid #21262d; padding-top: 20px; color: #f85149; }
        .main { flex: 1; padding: 30px 40px; overflow-y: auto; max-height: 100vh; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { font-size: 26px; font-weight: 600; }
        .user-badge { background: #1c2333; padding: 8px 18px; border-radius: 20px; font-size: 14px; border: 1px solid #30363d; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; }
        .stat-card .label { font-size: 13px; color: #8b949e; text-transform: uppercase; }
        .stat-card .value { font-size: 32px; font-weight: 700; margin-top: 6px; }
        .stat-card.danger .value { color: #f85149; }
        .stat-card.success .value { color: #3fb950; }
        .stat-card.warning .value { color: #d29922; }
        .panel { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; margin-bottom: 30px; }
        .panel h2 { font-size: 18px; margin-bottom: 16px; color: #f0f6fc; }
        .panel h2 .badge { background: #21262d; font-size: 12px; padding: 2px 10px; border-radius: 12px; margin-left: 10px; font-weight: 400; }
        table { width: 100%; border-collapse: collapse; font-size: 14px; }
        th { text-align: left; padding: 10px 8px; border-bottom: 1px solid #21262d; color: #8b949e; }
        td { padding: 10px 8px; border-bottom: 1px solid #1c2333; }
        .risk-high { color: #f85149; font-weight: 600; }
        .risk-medium { color: #d29922; font-weight: 600; }
        .risk-low { color: #3fb950; font-weight: 600; }
        .status-badge { display: inline-block; padding: 2px 12px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .status-done { background: #1b3a24; color: #3fb950; }
        .status-pending { background: #2d2a1b; color: #d29922; }
        .btn { background: #238636; border: none; color: white; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .btn:hover { background: #2ea043; }
        .btn-sm { padding: 4px 12px; font-size: 12px; }
        .input-area { display: flex; gap: 12px; margin: 16px 0; }
        .input-area textarea { flex: 1; background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 12px; color: white; resize: vertical; font-family: monospace; }
        .input-area button { padding: 12px 30px; }
        .code-block { background: #0d1117; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 13px; white-space: pre-wrap; border: 1px solid #21262d; }
        .flex { display: flex; justify-content: space-between; align-items: center; }
        .hidden { display: none; }
        @media (max-width: 768px) { .sidebar { display: none; } .main { padding: 20px; } }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">AI <span>GLUE</span></div>
        <div class="nav-item active" onclick="switchTab('dashboard')"><span class="icon">📊</span> Dashboard</div>
        <div class="nav-item" onclick="switchTab('requests')"><span class="icon">📝</span> Requests</div>
        <div class="nav-item" onclick="switchTab('audit')"><span class="icon">🔍</span> Audit Trail</div>
        <div class="nav-item" onclick="switchTab('health')"><span class="icon">🖥️</span> System Health</div>
        <div class="nav-item logout" onclick="logout()"><span class="icon">🚪</span> Logout</div>
    </div>
    <div class="main">
        <div class="header">
            <h1 id="page-title">🛸 Mission Control</h1>
            <div class="user-badge">👤 <span id="username">Admin</span></div>
        </div>
        <div id="tab-dashboard">
            <div class="stats-grid" id="stats-grid">
                <div class="stat-card"><div class="label">Total Users</div><div class="value" id="stat-users">0</div></div>
                <div class="stat-card"><div class="label">Total Requests</div><div class="value" id="stat-requests">0</div></div>
                <div class="stat-card danger"><div class="label">High Risk Alerts</div><div class="value" id="stat-high">0</div></div>
                <div class="stat-card success"><div class="label">Success Rate</div><div class="value" id="stat-rate">0%</div></div>
            </div>
            <div class="panel">
                <h2>📌 Recent Activity <span class="badge">Live</span></h2>
                <div id="recent-activity">Loading...</div>
            </div>
            <div class="panel">
                <h2>📥 Quick Submit</h2>
                <div class="input-area">
                    <textarea id="quick-prompt" rows="2">print("Hello Mission Control!")</textarea>
                    <button class="btn" onclick="quickSubmit()">▶ Submit</button>
                </div>
                <div id="quick-result" class="hidden code-block"></div>
            </div>
        </div>
        <div id="tab-requests" class="hidden">
            <div class="panel">
                <div class="flex"><h2>📋 All Requests</h2> <button class="btn btn-sm" onclick="loadRequests()">🔄 Refresh</button></div>
                <div id="requests-table"><p>Loading...</p></div>
            </div>
        </div>
        <div id="tab-audit" class="hidden">
            <div class="panel">
                <h2>🔍 Audit Trail <span class="badge">Immutable</span></h2>
                <div id="audit-table"><p>Loading...</p></div>
            </div>
        </div>
        <div id="tab-health" class="hidden">
            <div class="stats-grid">
                <div class="stat-card"><div class="label">System Status</div><div class="value" style="color:#3fb950;">● LIVE</div></div>
                <div class="stat-card"><div class="label">Uptime</div><div class="value" id="uptime">0s</div></div>
                <div class="stat-card"><div class="label">CPU Usage</div><div class="value" id="cpu">0%</div></div>
                <div class="stat-card"><div class="label">Memory</div><div class="value" id="memory">0 MB</div></div>
            </div>
            <div class="panel">
                <h2>📜 Live Logs</h2>
                <div id="live-logs" class="code-block" style="height:300px; overflow-y:auto; font-size:12px;">Waiting...</div>
            </div>
        </div>
    </div>
    <script>
        let token = localStorage.getItem('token');
        let currentTab = 'dashboard';
        if (!token) { window.location.href = '/login-page'; }
        async function api(method, path, body) {
            const res = await fetch('http://localhost:5000' + path, {
                method, headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
                body: body ? JSON.stringify(body) : undefined
            });
            if (res.status === 401) { logout(); return; }
            return res.json();
        }
        function switchTab(tab) {
            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.querySelector(`.nav-item[onclick="switchTab('${tab}')"]`)?.classList.add('active');
            document.querySelectorAll('[id^="tab-"]').forEach(el => el.classList.add('hidden'));
            document.getElementById('tab-' + tab).classList.remove('hidden');
            currentTab = tab;
            if (tab === 'dashboard') loadDashboard();
            if (tab === 'requests') loadRequests();
            if (tab === 'audit') loadAudit();
            if (tab === 'health') loadHealth();
        }
        function logout() { localStorage.removeItem('token'); window.location.reload(); }
        async function loadDashboard() {
            try {
                const stats = await api('GET', '/api/stats');
                document.getElementById('stat-users').innerText = stats.users || 0;
                document.getElementById('stat-requests').innerText = stats.total_requests || 0;
                document.getElementById('stat-high').innerText = stats.high_risk || 0;
                document.getElementById('stat-rate').innerText = stats.success_rate || '0%';
                document.getElementById('username').innerText = stats.username || 'Admin';
                const recent = await api('GET', '/api/recent');
                let html = '';
                recent.slice(0, 5).forEach(r => {
                    html += `<div style="padding:8px 0; border-bottom:1px solid #1c2333;">${r.status === 'DONE' ? '✅' : '⏳'} <b>#${r.id}</b> ${r.prompt.substring(0,60)}... <span class="risk-${r.risk_level.toLowerCase()}">[${r.risk_level}]</span> <span class="status-badge status-${r.status.toLowerCase()}">${r.status}</span></div>`;
                });
                document.getElementById('recent-activity').innerHTML = html || 'No recent activity.';
            } catch(e) { console.error(e); }
        }
        async function quickSubmit() {
            const prompt = document.getElementById('quick-prompt').value;
            if (!prompt) return alert('Enter a prompt!');
            const data = await api('POST', '/submit', { prompt });
            if (data.id) {
                document.getElementById('quick-result').classList.remove('hidden');
                document.getElementById('quick-result').innerText = `✅ Submitted! Request #${data.id} | Status: ${data.status}`;
                setTimeout(() => { document.getElementById('quick-result').classList.add('hidden'); }, 3000);
                loadDashboard();
            }
        }
        async function loadRequests() {
            const data = await api('GET', '/requests');
            let html = `<table><tr><th>ID</th><th>Prompt</th><th>Risk</th><th>Status</th><th>Result</th><th>Action</th></tr>`;
            data.forEach(r => {
                html += `<tr><td>#${r.id}</td><td>${r.prompt.substring(0, 50)}...</td><td class="risk-${r.risk_level.toLowerCase()}">${r.risk_level}</td><td><span class="status-badge status-${r.status.toLowerCase()}">${r.status}</span></td><td>${r.result ? r.result.substring(0, 30) : '-'}</td><td>${r.status === 'APPROVED' || r.status === 'PENDING' ? `<button class="btn btn-sm" onclick="execReq(${r.id})">▶ Execute</button>` : '-'}</td></tr>`;
            });
            html += '</table>';
            document.getElementById('requests-table').innerHTML = data.length ? html : '<p>No requests found.</p>';
        }
        async function execReq(id) {
            const data = await api('POST', '/execute/' + id);
            if (data.result) alert('✅ Execution Complete!\n\n' + data.result);
            loadRequests(); loadDashboard();
        }
        async function loadAudit() {
            const data = await api('GET', '/api/audit');
            let html = `<table><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr>`;
            data.forEach(a => {
                html += `<tr><td>${new Date(a.timestamp).toLocaleString()}</td><td>User #${a.user_id}</td><td>${a.action}</td><td>${JSON.stringify(a.details).substring(0, 50)}</td></tr>`;
            });
            html += '</table>';
            document.getElementById('audit-table').innerHTML = data.length ? html : '<p>No audit logs found.</p>';
        }
        async function loadHealth() {
            const health = await api('GET', '/api/health');
            document.getElementById('uptime').innerText = health.uptime || '0s';
            document.getElementById('cpu').innerText = health.cpu || '0%';
            document.getElementById('memory').innerText = health.memory || '0 MB';
            document.getElementById('live-logs').innerText = health.logs || 'System healthy.';
        }
        window.onload = function() { loadDashboard(); };
        setInterval(() => { if (currentTab === 'dashboard') loadDashboard(); }, 10000);
    </script>
</body>
</html>
'''
with open('templates/dashboard.html', 'w', encoding='utf-8') as f:
    f.write(dashboard_html)

# ---- Write templates/login.html ----
login_html = '''
<!DOCTYPE html>
<html>
<head><title>Login</title>
<style>
body{background:#0d1117;color:white;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;}
.box{background:#161b22;padding:40px;border-radius:12px;border:1px solid #30363d;width:320px;}
input{width:100%;padding:10px;margin:8px 0;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:white;}
button{width:100%;padding:10px;background:#238636;border:none;border-radius:6px;color:white;font-weight:bold;cursor:pointer;}
.error{color:#f85149;margin-top:10px;}
</style>
</head>
<body>
<div class="box">
    <h2>🚀 AI Glue Login</h2>
    <input id="lu" placeholder="Username"><input id="lp" type="password" placeholder="Password">
    <button onclick="login()">Enter Mission Control</button>
    <p style="margin-top:10px;font-size:13px;color:#8b949e;">New? <a href="#" onclick="signup()" style="color:#58a6ff;">Create Account</a></p>
    <div id="msg" class="error"></div>
</div>
<script>
async function api(method, path, body) {
    const res = await fetch('http://localhost:5000'+path, { method, headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    return res.json();
}
async function login() {
    const data = await api('POST','/login', {username:document.getElementById('lu').value, password:document.getElementById('lp').value});
    if(data.access_token) { localStorage.setItem('token', data.access_token); window.location.href='/'; }
    else document.getElementById('msg').innerText = 'Invalid credentials';
}
async function signup() {
    const u=document.getElementById('lu').value, p=document.getElementById('lp').value;
    if(!u||!p) return alert('Fill fields');
    await api('POST','/signup',{username:u,password:p});
    alert('User created! Login now.');
}
</script>
</body>
</html>
'''
with open('templates/login.html', 'w', encoding='utf-8') as f:
    f.write(login_html)

# ---- Create static folder (if not exists) ----
os.makedirs('static', exist_ok=True)
# Create empty style.css if missing
if not os.path.exists('static/style.css'):
    with open('static/style.css', 'w', encoding='utf-8') as f:
        f.write('/* Custom styles if needed */')

print('All folders and files created successfully!')
print('Now run: py app.py')
print('Open: http://localhost:5000')