
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
