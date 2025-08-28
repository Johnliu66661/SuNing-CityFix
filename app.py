# app.py  —— 直接整份替换
import os
import uuid
import imghdr
from datetime import timedelta
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from sqlalchemy import desc, asc, inspect, text
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)

# >>> 关键：只使用 models.py 里的这“一套”数据库与模型 <<<
from models import db, AdminUser, User, Report, ReportEvent
from i18n import init_i18n

# ============ 配置 ============
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret')
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"sqlite:///{os.path.join(BASE_DIR,'app.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # ↑ 64MB，给视频留空间
    JSON_AS_ASCII = False
    # i18n
    BABEL_DEFAULT_LOCALE = 'zh'
    BABEL_SUPPORTED_LOCALES = ['zh', 'en']
    BABEL_TRANSLATION_DIRECTORIES = 'translations'

# 只创建一次 Flask 应用
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.from_object(Config)

# 路由末尾斜杠兼容
app.url_map.strict_slashes = False

# 目录
os.makedirs(UPLOAD_DIR, exist_ok=True)

# 扩展初始化（都挂在同一个 app 上）
db.init_app(app)
jwt = JWTManager(app)
init_i18n(app)

# ============ 启动时建表 & 默认管理员 & 轻量“迁移” ============
def ensure_report_columns():
    """无 Alembic 时，轻量给 SQLite 表加列：video_url / completion_video_url"""
    try:
        insp = inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('report')}
        to_add = []
        if 'video_url' not in cols:
            to_add.append("ALTER TABLE report ADD COLUMN video_url VARCHAR(255)")
        if 'completion_video_url' not in cols:
            to_add.append("ALTER TABLE report ADD COLUMN completion_video_url VARCHAR(255)")
        for sql in to_add:
            db.session.execute(text(sql))
        if to_add:
            db.session.commit()
    except Exception as e:
        # 失败不致命（比如不是 SQLite），只打日志
        print('[ensure_report_columns]', e)

with app.app_context():
    db.create_all()
    ensure_report_columns()
    if not AdminUser.query.filter_by(username='admin').first():
        a = AdminUser(username='admin', email='admin@example.com')
        a.set_password('adminpass')
        db.session.add(a)
        db.session.commit()

# ============ 常量 ============
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'mov', 'webm', 'mkv', 'avi'}

# 新增：待审核状态
ALLOWED_STATUSES = {'Pending', 'In Progress', 'Awaiting Review', 'Completed', 'Rejected'}
# “未完成/未关闭”的**，用于统计维护员负载
OPEN_STATUSES = ('Pending', 'In Progress', 'Awaiting Review')

# ============ 工具函数 ============
def _ext(filename: str) -> str:
    return (os.path.splitext(filename)[1] or '').lower().lstrip('.')

def allowed_image(filename: str) -> bool:
    return '.' in filename and _ext(filename) in ALLOWED_IMAGE_EXTENSIONS

def allowed_video(filename: str) -> bool:
    return '.' in filename and _ext(filename) in ALLOWED_VIDEO_EXTENSIONS

def save_image(file_storage):
    orig = secure_filename(file_storage.filename)
    ext = os.path.splitext(orig)[1].lower()
    filename = f"{uuid.uuid4().hex}{ext}"
    full_path = os.path.join(UPLOAD_DIR, filename)
    file_storage.save(full_path)
    if imghdr.what(full_path) not in ('png', 'jpeg', 'gif'):
        try:
            os.remove(full_path)
        except OSError:
            pass
        raise ValueError("Invalid image content")
    return f"uploads/{filename}"

def save_video(file_storage):
    """基础校验 + 保存视频到 uploads/，不做解码（轻量）"""
    orig = secure_filename(file_storage.filename)
    ext = os.path.splitext(orig)[1].lower()
    filename = f"{uuid.uuid4().hex}{ext}"
    full_path = os.path.join(UPLOAD_DIR, filename)
    file_storage.save(full_path)
    # 轻量校验：扩展名在白名单；MIME 前缀最好是 video/
    mime_ok = (file_storage.mimetype or '').startswith('video/')
    if not mime_ok and _ext(orig) not in ALLOWED_VIDEO_EXTENSIONS:
        try: os.remove(full_path)
        except OSError: pass
        raise ValueError("Invalid video content")
    return f"uploads/{filename}"

def role_required(role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            if claims.get("role") != role:
                return jsonify({"msg": f"Forbidden: need role '{role}'"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# 角色同义词归一化
def normalize_role_value(val: str) -> str:
    mapping = {
        "维护员": "maintainer", "維護員": "maintainer",
        "维修员": "maintainer", "維修員": "maintainer",
        "运维": "maintainer",   "運維": "maintainer",
        "维保": "maintainer",   "維保": "maintainer",
        "维修": "maintainer",   "維修": "maintainer",
        "maintainer": "maintainer",
        "用户": "user", "普通用户": "user", "user": "user",
    }
    raw = (val or "").strip().lower()
    return mapping.get(raw, raw)

def current_actor():
    claims = get_jwt()
    role = claims.get("role")
    identity = get_jwt_identity()  # "admin:1" / "user:2"
    prefix, id_str = identity.split(":")
    _id = int(id_str)
    uname = None
    if role in ('user', 'maintainer'):
        u = User.query.get(_id)
        uname = u.username if u else None
    elif role == 'admin':
        a = AdminUser.query.get(_id)
        uname = a.username if a else None
    return role, _id, uname

def log_event(report_id: int, event_type: str, content: str):
    try:
        role, _id, uname = current_actor()
    except Exception:
        role, uname = None, None
    ev = ReportEvent(
        report_id=report_id,
        event_type=event_type,
        content=(content or "")[:255] if content else None,
        actor_username=uname,
        actor_role=role
    )
    db.session.add(ev)

# ========= 自动派单：基于“维护员待办最少优先”，维护员自报自接 =========
def _open_load_of(username: str) -> int:
    """该维护员当前未完结任务数（待办负载）"""
    return Report.query.filter(
        Report.assigned_to == username,
        Report.status.in_(OPEN_STATUSES)
    ).count()

def choose_maintainer_for():
    """
    以“待办任务数”升序选择维护员；平局按用户名顺序。
    若无维护员，返回 None。
    """
    maintainers = User.query.filter_by(role='maintainer').all()
    if not maintainers:
        return None
    scored = []
    for m in maintainers:
        load = _open_load_of(m.username)
        scored.append((load, m.username))
    scored.sort(key=lambda x: (x[0], x[1]))
    return scored[0][1] if scored else None

def auto_assign_report(report_obj: Report, submitter_role: str, submitter_username: str):
    """
    自动派单核心：
    - 维护员自己上报：自报自接，并置为 In Progress
    - 否则：指派给待办最少的维护员；若无维护员则不指派
    返回 (assigned_to_username 或 None, auto_assigned: bool)
    """
    assigned_to = None
    auto_flag = False

    # 维护员自报自接
    if submitter_role == 'maintainer' and submitter_username:
        assigned_to = submitter_username
        report_obj.assigned_to = assigned_to
        if report_obj.status == 'Pending':
            report_obj.status = 'In Progress'
            log_event(report_obj.id, 'status_change', '状态更改为 In Progress（自报自接）')
        log_event(report_obj.id, 'assignment', f'自动指派给 {assigned_to}（自报自接）')
        auto_flag = True
        return assigned_to, auto_flag

    # 管理员/普通用户上报：派给待办最少的维护员
    best = choose_maintainer_for()
    if best:
        assigned_to = best
        report_obj.assigned_to = assigned_to
        if report_obj.status == 'Pending':
            report_obj.status = 'In Progress'
            log_event(report_obj.id, 'status_change', '状态更改为 In Progress（自动派单）')
        log_event(report_obj.id, 'assignment', f'自动指派给 {assigned_to}')
        auto_flag = True

    return assigned_to, auto_flag

# ============ 页面 ============
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

# ============ 认证（保持不变） ============
@app.route('/login', methods=['POST'])
def login_admin():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        return jsonify({"msg": "username and password are required"}), 400
    admin = AdminUser.query.filter_by(username=username).first()
    if admin and check_password_hash(admin.password_hash, password):
        token = create_access_token(
            identity=f"admin:{admin.id}",
            additional_claims={"role": "admin"},
            expires_delta=timedelta(hours=8)
        )
        return jsonify(access_token=token), 200
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/user/register', methods=['POST'])
def user_register():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    email = (data.get('email') or '').strip() or None
    if not username or not password:
        return jsonify({"msg":"username and password are required"}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"msg":"username already exists"}), 409
    u = User(username=username, email=email)
    u.password_hash = generate_password_hash(password)
    db.session.add(u)
    db.session.commit()
    return jsonify({"msg":"registered successfully"}), 201

@app.route('/user/login', methods=['POST'])
def user_login():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = (data.get('password') or '').strip()
    if not username or not password:
        return jsonify({"msg":"username and password are required"}), 400
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        role_claim = user.role if user.role in ('user','maintainer') else 'user'
        token = create_access_token(
            identity=f"user:{user.id}",
            additional_claims={"role": role_claim},
            expires_delta=timedelta(hours=12)
        )
        return jsonify(access_token=token), 200
    return jsonify({"msg":"Bad username or password"}), 401

@app.route('/me', methods=['GET'])
@jwt_required()
def me():
    role, uid, uname = current_actor()
    base = {"role": role, "id": uid, "username": uname}
    if role in ('user','maintainer'):
        u = User.query.get(uid)
        if not u: return jsonify({"msg":"user not found"}), 404
        base.update({"email": u.email, "phone": u.phone, "created_at": u.created_at.isoformat() if u.created_at else None})
    elif role == 'admin':
        a = AdminUser.query.get(uid)
        if not a: return jsonify({"msg":"admin not found"}), 404
        base.update({"email": a.email, "created_at": a.created_at.isoformat() if a.created_at else None})
    return jsonify(base), 200

# ============ 报修公共：删除文件帮助 ============
def _remove_file(rel_path: str):
    if not rel_path:
        return
    full = os.path.join(UPLOAD_DIR, os.path.basename(rel_path))
    if os.path.exists(full):
        try:
            os.remove(full)
        except OSError:
            pass

def _hard_delete_report(report: Report):
    """物理删除：文件 + 事件 + 记录"""
    # 清掉图片/视频
    for rel in (
        report.photo_url,
        report.completion_photo_url,
        getattr(report, 'video_url', None),
        getattr(report, 'completion_video_url', None),
    ):
        _remove_file(rel)
    # 删事件
    ReportEvent.query.filter_by(report_id=report.id).delete(synchronize_session=False)
    # 删报修
    db.session.delete(report)

# ============ 报修 ============
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(e):
    return jsonify({"msg":"File too large"}), 413

@app.route('/reports', methods=['POST'])
@jwt_required()
def create_report():
    role, uid, submitter_name = current_actor()
    description = request.form.get('description')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    report_type = request.form.get('report_type')
    if not all([description, latitude, longitude, report_type]):
        return jsonify({"msg":"Missing required fields"}), 400
    try:
        latitude = float(latitude); longitude = float(longitude)
        if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
            raise ValueError
    except ValueError:
        return jsonify({"msg":"Invalid latitude or longitude"}), 400

    photo_rel = None
    video_rel = None

    photo = request.files.get('photo')
    if photo and photo.filename:
        if not allowed_image(photo.filename):
            return jsonify({"msg":"Invalid image type"}), 400
        try:
            photo_rel = save_image(photo)
        except ValueError:
            return jsonify({"msg":"Invalid image content"}), 400

    video = request.files.get('video')
    if video and video.filename:
        if not allowed_video(video.filename):
            return jsonify({"msg":"Invalid video type"}), 400
        try:
            video_rel = save_video(video)
        except ValueError:
            return jsonify({"msg":"Invalid video content"}), 400

    user_id = uid if role in ('user','maintainer') else None

    r = Report(description=description, latitude=latitude, longitude=longitude,
               report_type=report_type, photo_url=photo_rel, user_id=user_id)
    if hasattr(r, 'video_url'):
        r.video_url = video_rel

    db.session.add(r)
    db.session.flush()  # 为获取 r.id、写入事件做准备
    log_event(r.id, 'created', '创建报修')

    # —— 自动派单（维护员自报自接；否则派给待办最少者；若无维护员则不指派） —— #
    assigned_to, auto_flag = auto_assign_report(r, role, submitter_name)

    db.session.commit()

    resp_body = {
        "msg":"Report submitted",
        "report_id": r.id,
        "status": r.status,
        "assigned_to": assigned_to,
        "auto_assigned": bool(auto_flag)
    }
    resp = jsonify(resp_body)
    resp.headers['Location'] = f"/reports/{r.id}"
    return resp, 201

@app.route('/reports', methods=['GET'])
@jwt_required()
def list_reports():
    role, uid, uname = current_actor()
    query = Report.query
    if role == 'user':
        query = query.filter(Report.user_id == uid)

    status_filter = request.args.get('status')
    rt_filter = request.args.get('report_type')
    search_description = request.args.get('search')
    assigned_to = request.args.get('assigned_to')
    bbox = request.args.get('bbox')

    if status_filter and status_filter != 'All':
        query = query.filter(Report.status == status_filter)
    if rt_filter:
        query = query.filter(Report.report_type.ilike(f"%{rt_filter}%"))
    if search_description:
        query = query.filter(Report.description.ilike(f"%{search_description}%"))
    if assigned_to:
        query = query.filter(Report.assigned_to == assigned_to)
    if bbox:
        try:
            west, south, east, north = [float(x) for x in bbox.split(',')]
            query = query.filter(Report.longitude >= west, Report.longitude <= east,
                                 Report.latitude >= south, Report.latitude <= north)
        except Exception:
            return jsonify({"msg":"invalid bbox format"}), 400

    sort_by = request.args.get('sort_by','created_at')
    order = request.args.get('order','desc')
    col = {'created_at':Report.created_at,'updated_at':Report.updated_at,'status':Report.status}.get(sort_by, Report.created_at)
    query = query.order_by(asc(col) if order=='asc' else desc(col))

    page = request.args.get('page',1,type=int)
    per_page = request.args.get('per_page',6,type=int)
    per_page = max(1, min(per_page, 100))
    p = query.paginate(page=page, per_page=per_page, error_out=False)

    def dump(r: Report):
        return {
            "id": r.id,
            "description": r.description,
            "latitude": r.latitude,
            "longitude": r.longitude,
            "report_type": r.report_type,
            "photo_url": r.photo_url,
            "completion_photo_url": r.completion_photo_url,
            "video_url": getattr(r, 'video_url', None),
            "completion_video_url": getattr(r, 'completion_video_url', None),
            "assigned_to": r.assigned_to,
            "status": r.status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
            "user_id": r.user_id
        }

    return jsonify({
        "reports":[dump(x) for x in p.items],
        "pagination":{
            "total_items":p.total, "total_pages":p.pages, "current_page":p.page,
            "per_page":p.per_page, "has_next":p.has_next, "has_prev":p.has_prev
        }
    }), 200

@app.route('/reports/<int:report_id>', methods=['GET'])
@jwt_required()
def get_report(report_id):
    role, uid, _ = current_actor()
    r = Report.query.get_or_404(report_id)
    if role == 'user' and r.user_id != uid:
        return jsonify({"msg":"Forbidden"}), 403
    return jsonify({
        "id": r.id,
        "description": r.description,
        "latitude": r.latitude,
        "longitude": r.longitude,
        "report_type": r.report_type,
        "photo_url": r.photo_url,
        "completion_photo_url": r.completion_photo_url,
        "video_url": getattr(r, 'video_url', None),
        "completion_video_url": getattr(r, 'completion_video_url', None),
        "assigned_to": r.assigned_to,
        "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        "user_id": r.user_id
    }), 200

@app.route('/reports/<int:report_id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_report_admin(report_id):
    r = Report.query.get_or_404(report_id)
    data = request.get_json(silent=True) or {}

    if 'status' in data:
        s = data['status']
        if s not in ALLOWED_STATUSES:
            return jsonify({"msg":"invalid status"}), 400
        if r.status != s:
            r.status = s
            log_event(report_id, 'status_change', f'状态更改为 {s}')

    if 'description' in data:
        desc_text = (data['description'] or '').strip()
        if not desc_text:
            return jsonify({"msg":"description cannot be empty"}), 400
        if r.description != desc_text:
            r.description = desc_text
            log_event(report_id, 'comment', f'更新描述为: {desc_text}')

    if 'report_type' in data:
        rt = (data['report_type'] or '').strip()
        if not rt:
            return jsonify({"msg":"report_type cannot be empty"}), 400
        if r.report_type != rt:
            r.report_type = rt
            log_event(report_id, 'comment', f'更新类型为: {rt}')

    db.session.commit()
    return jsonify({"msg":"updated","status":r.status}), 200

@app.route('/reports/<int:report_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_report(report_id):
    r = Report.query.get_or_404(report_id)
    _hard_delete_report(r)
    db.session.commit()
    return jsonify({"msg":"deleted"}), 200

@app.route('/reports/<int:report_id>/assign', methods=['POST'])
@jwt_required()
@role_required('admin')
def assign_report(report_id):
    r = Report.query.get_or_404(report_id)
    data = request.get_json(silent=True) or {}
    target_name = (data.get('assigned_to') or '').strip()
    if not target_name:
        return jsonify({"msg":"assigned_to required"}), 400
    maint = User.query.filter_by(username=target_name, role='maintainer').first()
    if not maint:
        return jsonify({"msg":"maintainer not found"}), 404
    r.assigned_to = maint.username
    if r.status == 'Pending':
        r.status = 'In Progress'
        log_event(report_id, 'status_change', '状态更改为 In Progress（手动指派）')
    log_event(report_id, 'assignment', f'指派给 {maint.username}')
    db.session.commit()
    return jsonify({"msg":"assigned","report_id":r.id,"assigned_to":r.assigned_to}), 200

def maintainer_can_transition(old, new):
    # 维护员：允许从 Pending / In Progress 进入 Awaiting Review（提交完工材料）
    allowed = {
        'Pending': {'In Progress', 'Rejected', 'Awaiting Review'},
        'In Progress': {'Completed', 'Rejected', 'Awaiting Review'},
        'Awaiting Review': set(),  # 待审核期不可再由维护员改状态
        'Completed': set(),
        'Rejected': set()
    }
    return new in allowed.get(old, set())

@app.route('/reports/<int:report_id>/maintainer', methods=['POST'])
@jwt_required()
def maintainer_update(report_id):
    role, _, uname = current_actor()
    if role != 'maintainer':
        return jsonify({"msg":"Forbidden: maintainer only"}), 403
    r = Report.query.get_or_404(report_id)
    if r.assigned_to != uname:
        return jsonify({"msg":"Forbidden: not your assignment"}), 403

    status = None
    uploaded = False

    if request.content_type and request.content_type.startswith('application/json'):
        # 维护员纯状态更新（不含文件）
        data = request.get_json(silent=True) or {}
        status = (data.get('status') or '').strip()
        if status not in ALLOWED_STATUSES:
            return jsonify({"msg":"invalid status"}), 400
        if not maintainer_can_transition(r.status, status):
            return jsonify({"msg":f"illegal transition {r.status} -> {status}"}), 400
        if r.status != status:
            r.status = status
            log_event(report_id, 'status_change', f'状态更改为 {status}')

    else:
        # 维护员提交完工材料（图片/视频），若未显式传 status，则自动置为 Awaiting Review
        status = (request.form.get('status') or '').strip()
        if status and status not in ALLOWED_STATUSES:
            return jsonify({"msg":"invalid status"}), 400
        if status and not maintainer_can_transition(r.status, status):
            return jsonify({"msg":f"illegal transition {r.status} -> {status}"}), 400

        completion = request.files.get('completion_photo')
        if completion and completion.filename:
            if not allowed_image(completion.filename):
                return jsonify({"msg":"Invalid file type"}), 400
            try:
                rel = save_image(completion)
            except ValueError:
                return jsonify({"msg":"Invalid image content"}), 400
            r.completion_photo_url = rel
            uploaded = True
            log_event(report_id, 'upload', '上传完工图')

        completion_video = request.files.get('completion_video')
        if completion_video and completion_video.filename:
            if not allowed_video(completion_video.filename):
                return jsonify({"msg":"Invalid video type"}), 400
            try:
                vrel = save_video(completion_video)
            except ValueError:
                return jsonify({"msg":"Invalid video content"}), 400
            if hasattr(r, 'completion_video_url'):
                r.completion_video_url = vrel
            uploaded = True
            log_event(report_id, 'upload', '上传完工视频')

        # 若上传了材料且未显式给状态，自动进入“待审核”
        if uploaded and not status:
            status = 'Awaiting Review'

        if status:
            if r.status != status:
                r.status = status
                log_event(report_id, 'status_change', f'状态更改为 {status}')

        if not status and not uploaded:
            return jsonify({"msg":"no changes"}), 400

    db.session.commit()
    return jsonify({
        "msg":"maintainer updated",
        "report_id":r.id,
        "status":r.status,
        "completion_photo_url": r.completion_photo_url,
        "completion_video_url": getattr(r, 'completion_video_url', None)
    }), 200

@app.route('/reports/<int:report_id>/approve', methods=['POST'])
@jwt_required()
@role_required('admin')
def approve_and_delete_report(report_id):
    """管理员审核通过：置 Completed 并立即物理删除该报修"""
    r = Report.query.get_or_404(report_id)
    if r.status != 'Awaiting Review':
        return jsonify({"msg":"invalid state: only Awaiting Review can be approved"}), 400

    # 记录状态变化与审核通过事件（随后会被物理删除，主要用于实时通知或审计流水）
    r.status = 'Completed'
    log_event(report_id, 'status_change', '状态更改为 Completed（审核通过）')
    log_event(report_id, 'approve', '管理员审核通过并自动删除')

    # 物理删除（文件/事件/记录）
    _hard_delete_report(r)
    db.session.commit()

    return jsonify({"msg":"approved_and_deleted", "deleted": True, "report_id": report_id}), 200

@app.route('/reports/<int:report_id>/events', methods=['GET'])
@jwt_required()
def list_report_events(report_id):
    role, uid, _ = current_actor()
    r = Report.query.get_or_404(report_id)
    if role == 'user' and r.user_id != uid:
        return jsonify({"msg":"Forbidden"}), 403
    events = ReportEvent.query.filter_by(report_id=report_id).order_by(desc(ReportEvent.created_at)).all()
    return jsonify([{
        "id": e.id,
        "event_type": e.event_type,
        "content": e.content,
        "actor_username": e.actor_username,
        "actor_role": e.actor_role,
        "created_at": e.created_at.isoformat()
    } for e in events]), 200

@app.route('/reports/<int:report_id>/events', methods=['POST'])
@jwt_required()
def add_report_comment(report_id):
    role, uid, uname = current_actor()
    r = Report.query.get_or_404(report_id)
    if role == 'user' and r.user_id != uid:
        return jsonify({"msg":"Forbidden"}), 403
    if role == 'maintainer' and r.assigned_to != uname:
        return jsonify({"msg":"Forbidden"}), 403

    data = request.get_json(silent=True) or {}
    content = (data.get('content') or '').strip()
    if not content:
        return jsonify({"msg":"content required"}), 400

    log_event(report_id, 'comment', content)
    db.session.commit()
    return jsonify({"msg":"comment added"}), 201

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False, threaded=True)
# --- 在 import 区域下方加入 ---
def get_dashboard_alerts():
    """首页告警卡片：中英双语同时展示"""
    return [
        {
            "category": {"zh": "告警", "en": "Alerts"},
            "title":    {"zh": "连续 2 天 SLA < 92%", "en": "SLA < 92% for 2 consecutive days"},
            "ago":      {"zh": "刚刚", "en": "just now"},
        },
        {
            "category": {"zh": "逾期", "en": "Overdue"},
            "title":    {"zh": "逾期工单 > 10", "en": "Overdue tickets > 10"},
            "ago":      {"zh": "15 分钟前", "en": "15 minutes ago"},
        },
        {
            "category": {"zh": "类型", "en": "Category"},
            "title":    {"zh": "某类型激增：路灯", "en": "Type spike: street lights"},
            "ago":      {"zh": "1 小时前", "en": "1 hour ago"},
        },
    ]

@app.get("/api/alerts")
def api_alerts():
    return jsonify(get_dashboard_alerts())
