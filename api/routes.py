
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
