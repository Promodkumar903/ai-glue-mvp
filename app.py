from flask import Flask, request, jsonify, render_template_string
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import jwt
import os
import subprocess
import tempfile
import time
import psutil
from passlib.context import CryptContext

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "super-secret-key-change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ai_glue.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
CORS(app)

db = SQLAlchemy(app)
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
start_time = time.time()

# ---------- MODELS ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")

class RequestLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    plan = db.Column(db.JSON)
    status = db.Column(db.String(20), default="PENDING")
    risk_level = db.Column(db.String(20), default="LOW")
    result = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50))
    details = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ---------- CREATE TABLES + DEFAULT ADMIN ----------
def create_default_admin():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password_hash=pwd.hash("admin"), role="admin")
            db.session.add(admin)
            db.session.commit()
            print("✅ Default admin created: admin / admin")
        else:
            print("✅ Admin already exists")

# ---------- HELPERS ----------
def hash_password(password):
    return pwd.hash(password)

def verify_password(password, password_hash):
    try:
        return pwd.verify(password, password_hash)
    except Exception:
        return False

def create_token(user_id):
    return jwt.encode(
        {"sub": str(user_id), "exp": datetime.utcnow() + timedelta(hours=24)},
        app.config["SECRET_KEY"],
        algorithm="HS256"
    )

def decode_token(token):
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        token = auth.split(" ", 1)[1].strip()
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        try:
            user_id = int(payload["sub"])
        except Exception:
            return jsonify({"error": "Invalid token"}), 401
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({"error": "User not found"}), 401
        return f(user, *args, **kwargs)
    return decorated

def assess_risk(prompt):
    high = ["delete", "drop", "rm -rf", "format", "sudo"]
    if any(k in prompt.lower() for k in high):
        return "HIGH"
    return "LOW"

def run_code(code):
    try:
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, "script.py")
            with open(script_path, "w", encoding="utf-8") as fp:
                fp.write(code)
            result = subprocess.run(
                ["python", script_path],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=tmp
            )
            return result.stdout if result.stdout else result.stderr
    except subprocess.TimeoutExpired:
        return "Error: Execution timed out."
    except Exception as e:
        return f"Error: {str(e)}"

# ---------- HTML TEMPLATE (same as before, but with fixed JS) ----------
HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AI Glue - Mission Control</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; font-family:system-ui, sans-serif; }
        body { background:#0d1117; color:#c9d1d9; display:flex; min-height:100vh; }
        .sidebar { width:220px; background:#161b22; padding:20px; border-right:1px solid #30363d; min-height:100vh; }
        .sidebar .logo { font-size:22px; font-weight:700; color:#58a6ff; margin-bottom:30px; }
        .sidebar .logo span { color:#f0883e; }
        .sidebar .item { padding:12px 16px; border-radius:8px; cursor:pointer; margin:4px 0; user-select:none; }
        .sidebar .item:hover { background:#1c2333; }
        .sidebar .item.active { background:#1c2333; color:#f0f6fc; }
        .sidebar .item .icon { margin-right:12px; }
        .sidebar .logout { margin-top:40px; border-top:1px solid #30363d; padding-top:20px; color:#f85149; }
        .main { flex:1; padding:30px 40px; overflow-y:auto; max-height:100vh; }
        .header { display:flex; justify-content:space-between; align-items:center; margin-bottom:20px; }
        .header h1 { font-size:24px; }
        .badge { background:#1c2333; padding:6px 16px; border-radius:20px; font-size:13px; border:1px solid #30363d; }
        .stats { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:20px 0; }
        .stat-card { background:#161b22; padding:18px; border-radius:12px; border:1px solid #30363d; }
        .stat-card .num { font-size:28px; font-weight:700; margin-top:4px; }
        .stat-card .label { font-size:13px; color:#8b949e; text-transform:uppercase; }
        .stat-card.danger .num { color:#f85149; }
        .stat-card.success .num { color:#3fb950; }
        .panel { background:#161b22; padding:20px; border-radius:12px; border:1px solid #30363d; margin:20px 0; }
        .panel h3 { margin-bottom:12px; }
        .btn { background:#238636; border:none; color:white; padding:8px 20px; border-radius:6px; cursor:pointer; font-size:13px; }
        .btn:hover { background:#2ea043; }
        .btn-sm { padding:4px 12px; font-size:12px; }
        textarea { background:#0d1117; border:1px solid #30363d; color:white; padding:10px; border-radius:6px; width:100%; resize:vertical; }
        .hidden { display:none !important; }
        table { width:100%; border-collapse:collapse; font-size:14px; }
        th { text-align:left; padding:10px 8px; border-bottom:1px solid #30363d; color:#8b949e; }
        td { padding:10px 8px; border-bottom:1px solid #21262d; }
        .risk-high { color:#f85149; font-weight:600; }
        .risk-low { color:#3fb950; }
        .status-done { background:#1b3a24; color:#3fb950; padding:2px 12px; border-radius:12px; font-size:12px; display:inline-block; }
        .status-pending { background:#2d2a1b; color:#d29922; padding:2px 12px; border-radius:12px; font-size:12px; display:inline-block; }
        .status-approved { background:#172b3a; color:#58a6ff; padding:2px 12px; border-radius:12px; font-size:12px; display:inline-block; }
        .status-running { background:#2d2a1b; color:#d29922; padding:2px 12px; border-radius:12px; font-size:12px; display:inline-block; }
        .flex { display:flex; justify-content:space-between; align-items:center; }
        .mt-10 { margin-top:10px; }
        .code-block { background:#0d1117; padding:12px; border-radius:8px; font-family:monospace; font-size:13px; border:1px solid #21262d; white-space:pre-wrap; }
        @media (max-width:900px) { .stats { grid-template-columns:repeat(2,1fr); } .sidebar { width:180px; } .main { padding:20px; } }
    </style>
</head>
<body>
<div class="sidebar">
    <div class="logo">AI <span>GLUE</span></div>
    <div class="item active" data-tab="dashboard"><span class="icon">[-]</span> Dashboard</div>
    <div class="item" data-tab="requests"><span class="icon">[-]</span> Requests</div>
    <div class="item" data-tab="audit"><span class="icon">[-]</span> Audit Trail</div>
    <div class="item" data-tab="health"><span class="icon">[-]</span> System Health</div>
    <div class="item logout" id="logoutBtn"><span class="icon">[x]</span> Logout</div>
</div>
<div class="main">
    <div class="header">
        <h1>Mission Control</h1>
        <div class="badge">User: <span id="username">Loading...</span></div>
    </div>
    <div id="tab-dashboard">
        <div class="stats">
            <div class="stat-card"><div class="label">Total Users</div><div class="num" id="stat-users">0</div></div>
            <div class="stat-card"><div class="label">Total Requests</div><div class="num" id="stat-requests">0</div></div>
            <div class="stat-card danger"><div class="label">High Risk</div><div class="num" id="stat-high">0</div></div>
            <div class="stat-card success"><div class="label">Success Rate</div><div class="num" id="stat-rate">0%</div></div>
        </div>
        <div class="panel"><h3>Recent Activity</h3><div id="recent-activity">Loading...</div></div>
        <div class="panel">
            <h3>Quick Submit</h3>
            <textarea id="quick-prompt" rows="2">print("Hello AI Glue!")</textarea>
            <button class="btn mt-10" id="submitBtn">Submit</button>
            <div id="quick-result" class="mt-10 code-block hidden"></div>
        </div>
    </div>
    <div id="tab-requests" class="hidden">
        <div class="panel">
            <div class="flex"><h3>All Requests</h3> <button class="btn btn-sm" id="refreshReqs">Refresh</button></div>
            <div id="requests-table">Loading...</div>
        </div>
    </div>
    <div id="tab-audit" class="hidden">
        <div class="panel"><h3>Audit Trail</h3><div id="audit-table">Loading...</div></div>
    </div>
    <div id="tab-health" class="hidden">
        <div class="stats">
            <div class="stat-card success"><div class="label">Status</div><div class="num" style="font-size:20px;">LIVE</div></div>
            <div class="stat-card"><div class="label">Uptime</div><div class="num" id="uptime" style="font-size:20px;">0s</div></div>
            <div class="stat-card"><div class="label">CPU</div><div class="num" id="cpu" style="font-size:20px;">0%</div></div>
            <div class="stat-card"><div class="label">Memory</div><div class="num" id="memory" style="font-size:20px;">0 MB</div></div>
        </div>
        <div class="panel"><h3>Live Logs</h3><div id="live-logs" class="code-block" style="height:250px; overflow-y:auto;">Waiting...</div></div>
    </div>
</div>
<script>
var BASE = window.location.origin;
var token = localStorage.getItem('token');
if (!token) { window.location.href = '/login-page'; }

function logout() {
    localStorage.removeItem('token');
    window.location.reload();
}
window.logout = logout;

function api(method, path, body) {
    var options = {
        method: method,
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }
    };
    if (body) options.body = JSON.stringify(body);
    return fetch(BASE + path, options)
        .then(function(res) {
            if (res.status === 401) { logout(); return null; }
            return res.json().catch(function() { return null; });
        });
}

function switchTab(tab) {
    var tabs = ['dashboard','requests','audit','health'];
    for (var i=0;i<tabs.length;i++) {
        var el = document.getElementById('tab-' + tabs[i]);
        if (el) el.classList.add('hidden');
    }
    var target = document.getElementById('tab-' + tab);
    if (target) target.classList.remove('hidden');
    var items = document.querySelectorAll('.sidebar .item');
    for (var j=0;j<items.length;j++) {
        items[j].classList.remove('active');
    }
    var activeItem = document.querySelector('.sidebar .item[data-tab="' + tab + '"]');
    if (activeItem) activeItem.classList.add('active');
    if (tab === 'dashboard') loadDashboard();
    else if (tab === 'requests') loadRequests();
    else if (tab === 'audit') loadAudit();
    else if (tab === 'health') loadHealth();
}
window.switchTab = switchTab;

function loadDashboard() {
    api('GET','/api/stats').then(function(s) {
        if (s) {
            document.getElementById('stat-users').innerText = s.users || 0;
            document.getElementById('stat-requests').innerText = s.total_requests || 0;
            document.getElementById('stat-high').innerText = s.high_risk || 0;
            document.getElementById('stat-rate').innerText = s.success_rate || '0%';
            document.getElementById('username').innerText = s.username || 'Admin';
        }
    });
    api('GET','/api/recent').then(function(r) {
        var html = '';
        if (r && r.length) {
            for (var i=0;i<r.length;i++) {
                var x = r[i];
                html += '<div style="padding:6px 0; border-bottom:1px solid #1c2333;">';
                html += (x.status === 'DONE' ? 'OK' : '--') + ' #' + x.id + ' ' + x.prompt.substring(0,55) + '... [' + x.risk_level + '] ';
                html += '<span class="status-' + x.status.toLowerCase() + '">' + x.status + '</span>';
                html += '</div>';
            }
        } else { html = 'No activity yet.'; }
        document.getElementById('recent-activity').innerHTML = html;
    });
}
window.loadDashboard = loadDashboard;

function submitReq() {
    var prompt = document.getElementById('quick-prompt').value;
    if (!prompt) { alert('Enter a prompt!'); return; }
    api('POST','/submit',{prompt:prompt}).then(function(data) {
        if (data && data.id) {
            var el = document.getElementById('quick-result');
            el.classList.remove('hidden');
            el.innerText = 'Request #' + data.id + ' | Status: ' + data.status;
            setTimeout(function(){el.classList.add('hidden');},3000);
            loadDashboard();
        }
    });
}
window.submitReq = submitReq;

function loadRequests() {
    api('GET','/requests').then(function(data) {
        if (!data || !data.length) {
            document.getElementById('requests-table').innerHTML = '<p>No requests found.</p>';
            return;
        }
        var html = '<table><tr><th>ID</th><th>Prompt</th><th>Risk</th><th>Status</th><th>Action</th></tr>';
        for (var i=0;i<data.length;i++) {
            var r = data[i];
            html += '<tr><td>#'+r.id+'</td><td>'+r.prompt.substring(0,45)+'...</td>';
            html += '<td class="risk-'+r.risk_level.toLowerCase()+'">'+r.risk_level+'</td>';
            html += '<td><span class="status-'+r.status.toLowerCase()+'">'+r.status+'</span></td><td>';
            if (r.status === 'APPROVED' || r.status === 'PENDING') {
                html += '<button class="btn btn-sm" onclick="execReq('+r.id+')">Execute</button>';
            } else { html += '-'; }
            html += '</td></tr>';
        }
        html += '</table>';
        document.getElementById('requests-table').innerHTML = html;
    });
}
window.loadRequests = loadRequests;

function execReq(id) {
    api('POST','/execute/'+id).then(function(data) {
        if (data && data.result) {
            alert('Result: ' + data.result);
        } else if (data && data.error) {
            alert('Error: ' + data.error);
        }
        loadRequests();
        loadDashboard();
    });
}
window.execReq = execReq;

function loadAudit() {
    api('GET','/api/audit').then(function(data) {
        if (!data || !data.length) {
            document.getElementById('audit-table').innerHTML = '<p>No audit logs found.</p>';
            return;
        }
        var html = '<table><tr><th>Time</th><th>Action</th><th>Details</th></tr>';
        for (var i=0;i<data.length;i++) {
            var a = data[i];
            html += '<tr><td>'+new Date(a.timestamp).toLocaleString()+'</td>';
            html += '<td>'+a.action+'</td>';
            html += '<td>'+JSON.stringify(a.details).substring(0,50)+'</td></tr>';
        }
        html += '</table>';
        document.getElementById('audit-table').innerHTML = html;
    });
}
window.loadAudit = loadAudit;

function loadHealth() {
    api('GET','/api/health').then(function(data) {
        if (data) {
            document.getElementById('uptime').innerText = data.uptime || '0s';
            document.getElementById('cpu').innerText = data.cpu || '0%';
            document.getElementById('memory').innerText = data.memory || '0 MB';
            document.getElementById('live-logs').innerText = data.logs || 'System operational.';
        }
    });
}
window.loadHealth = loadHealth;

document.addEventListener('DOMContentLoaded', function() {
    var items = document.querySelectorAll('.sidebar .item[data-tab]');
    for (var i=0;i<items.length;i++) {
        items[i].addEventListener('click', function(e) {
            var tab = this.getAttribute('data-tab');
            if (tab) switchTab(tab);
        });
    }
    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('submitBtn').addEventListener('click', submitReq);
    document.getElementById('refreshReqs').addEventListener('click', loadRequests);
    switchTab('dashboard');
    setInterval(function() {
        var dash = document.getElementById('tab-dashboard');
        if (dash && !dash.classList.contains('hidden')) { loadDashboard(); }
    }, 10000);
});
</script>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login - AI Glue</title>
    <style>
        body { background:#0d1117; color:#fff; display:flex; justify-content:center; align-items:center; height:100vh; font-family:system-ui, sans-serif; }
        .box { background:#161b22; padding:40px; border-radius:12px; border:1px solid #30363d; width:320px; }
        .box h2 { color:#58a6ff; margin-bottom:20px; }
        input { width:100%; padding:12px; margin:8px 0; background:#0d1117; border:1px solid #30363d; border-radius:6px; color:#fff; font-size:14px; }
        button { width:100%; padding:12px; background:#238636; border:0; border-radius:6px; color:#fff; font-weight:bold; font-size:15px; cursor:pointer; }
        button:hover { background:#2ea043; }
        a { color:#58a6ff; cursor:pointer; }
        .msg { color:#f85149; margin-top:10px; }
    </style>
</head>
<body>
<div class="box">
    <h2>AI Glue</h2>
    <input id="u" placeholder="Username">
    <input id="p" type="password" placeholder="Password">
    <button id="loginBtn">Enter Mission Control</button>
    <p style="margin-top:12px; font-size:14px; color:#8b949e;">New? <a id="signupLink">Create Account</a></p>
    <div id="msg" class="msg"></div>
</div>
<script>
var BASE = window.location.origin;
function api(method, path, body) {
    return fetch(BASE + path, {
        method: method,
        headers: { 'Content-Type': 'application/json' },
        body: body ? JSON.stringify(body) : undefined
    }).then(function(res) { return res.json(); });
}
function doLogin() {
    var u = document.getElementById('u').value;
    var p = document.getElementById('p').value;
    if (!u || !p) return;
    api('POST', '/login', { username: u, password: p }).then(function(d) {
        if (d.access_token) {
            localStorage.setItem('token', d.access_token);
            window.location.href = '/';
        } else {
            document.getElementById('msg').innerText = 'Invalid credentials';
        }
    });
}
function doSignup() {
    var u = document.getElementById('u').value;
    var p = document.getElementById('p').value;
    if (!u || !p) { alert('Fill all fields'); return; }
    api('POST', '/signup', { username: u, password: p }).then(function(d) {
        alert('User created! Login now.');
    });
}
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('loginBtn').addEventListener('click', doLogin);
    document.getElementById('signupLink').addEventListener('click', doSignup);
});
</script>
</body>
</html>
'''

# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/login-page')
def login_page():
    return render_template_string(LOGIN_HTML)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    hashed = hash_password(password)
    user = User(username=username, password_hash=hashed, role="user")
    db.session.add(user)
    db.session.commit()
    return jsonify({"msg": "User created"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_token(user.id)
    return jsonify({"access_token": token, "username": user.username}), 200

@app.route('/submit', methods=['POST'])
@login_required
def submit(user):
    prompt = request.json.get('prompt')
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400
    plan = {"code_snippet": f"print('Running: {prompt[:30]}...')\nprint('Done!')"}
    req = RequestLog(user_id=user.id, prompt=prompt, plan=plan, risk_level=assess_risk(prompt), status="APPROVED")
    db.session.add(req)
    db.session.commit()
    audit = AuditLog(user_id=user.id, action="SUBMIT", details={"req_id": req.id})
    db.session.add(audit)
    db.session.commit()
    return jsonify({"id": req.id, "status": req.status})

@app.route('/execute/<int:req_id>', methods=['POST'])
@login_required
def execute(user, req_id):
    req = RequestLog.query.get(req_id)
    if not req:
        return jsonify({"error": "Not found"}), 404
    if req.user_id != user.id and user.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    req.status = "RUNNING"
    db.session.commit()
    output = run_code(req.plan.get("code_snippet", "print('No code')"))
    req.result = output
    req.status = "DONE"
    db.session.commit()
    audit = AuditLog(user_id=user.id, action="EXECUTE", details={"req_id": req_id})
    db.session.add(audit)
    db.session.commit()
    return jsonify({"status": "DONE", "result": output})

@app.route('/requests', methods=['GET'])
@login_required
def get_requests(user):
    q = RequestLog.query.filter_by(user_id=user.id) if user.role != "admin" else RequestLog.query
    requests = q.order_by(RequestLog.id.desc()).all()
    return jsonify([{
        "id": r.id,
        "prompt": r.prompt,
        "status": r.status,
        "risk_level": r.risk_level,
        "result": r.result
    } for r in requests])

@app.route('/api/stats')
@login_required
def stats(user):
    total = RequestLog.query.count()
    done = RequestLog.query.filter_by(status="DONE").count()
    return jsonify({
        "users": User.query.count(),
        "total_requests": total,
        "high_risk": RequestLog.query.filter_by(risk_level="HIGH").count(),
        "success_rate": f"{round(done/total*100 if total>0 else 0, 1)}%",
        "username": user.username
    })

@app.route('/api/recent')
@login_required
def recent(user):
    logs = RequestLog.query.order_by(RequestLog.id.desc()).limit(10).all()
    return jsonify([{
        "id": r.id,
        "prompt": r.prompt,
        "status": r.status,
        "risk_level": r.risk_level
    } for r in logs])

@app.route('/api/audit')
@login_required
def audit(user):
    q = AuditLog.query.filter_by(user_id=user.id) if user.role != "admin" else AuditLog.query
    logs = q.order_by(AuditLog.id.desc()).limit(50).all()
    return jsonify([{
        "user_id": l.user_id,
        "action": l.action,
        "details": l.details,
        "timestamp": l.timestamp.isoformat()
    } for l in logs])

@app.route('/api/health')
@login_required
def health(user):
    return jsonify({
        "uptime": str(timedelta(seconds=int(time.time() - start_time))),
        "cpu": f"{psutil.cpu_percent()}%",
        "memory": f"{round(psutil.virtual_memory().used / 1024 / 1024, 1)} MB",
        "logs": "All systems operational."
    })

# Create tables and default admin on startup
with app.app_context():
    db.create_all()
    create_default_admin()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)