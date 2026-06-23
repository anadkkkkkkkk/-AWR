import os, re, json, csv, sqlite3, hashlib, io, zipfile, base64, requests, datetime, threading
from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
import qrcode
from fpdf import FPDF
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'awr-fallback-dev-key-2025')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# ── Telegram Notifications ─────────────────────────────────
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT  = os.environ.get('TELEGRAM_CHAT_ID', '')

def send_telegram(message: str):
    """Send a Telegram message in a background thread so it never blocks requests."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    def _send():
        try:
            requests.post(
                f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage',
                json={'chat_id': TELEGRAM_CHAT, 'text': message, 'parse_mode': 'HTML'},
                timeout=8
            )
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()

def init_db():
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        is_paid INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        created_at TEXT
    )''')
    # Migrate existing DB — add columns if missing
    for col, defval in [('is_paid', '0'), ('is_admin', '0')]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER DEFAULT {defval}")
        except Exception:
            pass
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        dbms TEXT,
        tables TEXT,
        data TEXT,
        created_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT,
        details TEXT,
        ip TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def log_action(action, details, ip):
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("INSERT INTO logs (action, details, ip, created_at) VALUES (?, ?, ?, ?)",
              (action, details, ip, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def payment_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if not session.get('is_paid'):
            flash('⚠️ يجب تفعيل حسابك أولاً عبر الدفع. تواصل معنا على واتساب.', 'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

class SQLiLogParser:
    def __init__(self, raw_text):
        self.raw = raw_text
        self.data = {"dbms": "Unknown", "param": None, "tables": {}}
        self.parse()

    def parse(self):
        m = re.search(r'back-end DBMS(?:\s+is|\s*:)\s*([^\n]+)', self.raw)
        if m: self.data["dbms"] = m.group(1).strip()
        m = re.search(r'Parameter:\s*([\w]+)\s*\(GET\)', self.raw)
        if m: self.data["param"] = m.group(1)
        parts = re.split(r'Table:\s*(\w+)', self.raw)
        for i in range(1, len(parts), 2):
            table_name = parts[i]
            table_body = parts[i+1] if i+1 < len(parts) else ""
            cols = []
            header_match = re.search(r'\+----\+([\s\S]+?)\+----\+', table_body)
            if header_match:
                header_line = header_match.group(1).strip()
                candidates = [c.strip() for c in header_line.split('|') if c.strip()]
                cols = [c for c in candidates if c.isalpha() and len(c) > 1]
                if not cols: cols = ["id", "password", "username"]
            rows = []
            row_matches = re.findall(r'\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|', table_body)
            for r in row_matches:
                if r[0].strip().isdigit():
                    rows.append({
                        cols[0] if len(cols) > 0 else "col1": r[0].strip(),
                        cols[1] if len(cols) > 1 else "col2": r[1].strip(),
                        cols[2] if len(cols) > 2 else "col3": r[2].strip()
                    })
            if rows:
                self.data["tables"][table_name] = {"columns": cols, "rows": rows}

    def generate_recommendations(self):
        dbms = self.data.get("dbms", "").lower()
        if "sqlite" in dbms:
            return ["استخدم Prepared Statements مع PDO.", "فلتر المدخلات.", "قلل صلاحيات قاعدة البيانات."]
        elif "mysql" in dbms:
            return ["استخدم mysqli_prepare().", "فعّل WAF.", "طبق Least Privilege."]
        else:
            return ["استخدم Parameterized Queries.", "نقّي المدخلات.", "أجرِ VAPT دوري."]

    def save_report(self, user_id, filename):
        conn = sqlite3.connect('awr.db')
        c = conn.cursor()
        c.execute("INSERT INTO reports (user_id, filename, dbms, tables, data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                  (user_id, filename, self.data['dbms'], json.dumps(self.data['tables']), json.dumps(self.data), datetime.datetime.now().isoformat()))
        conn.commit()
        conn.close()

class PDF(FPDF):
    def header(self):
        self.set_fill_color(4, 8, 15)
        self.rect(0, 0, 210, 20, 'F')
        self.set_font('Arial', 'B', 14)
        self.set_text_color(0, 210, 255)
        self.cell(0, 12, 'AWR Security Labs - Security Report', 0, 1, 'C')
        self.set_text_color(200, 200, 200)
        self.set_font('Arial', '', 8)
        self.cell(0, 6, 'Penetration Testing & Vulnerability Assessment', 0, 1, 'C')
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(100, 100, 120)
        self.cell(0, 10, f'Page {self.page_no()} | AWR Security Labs | +967775113425 | Confidential', 0, 0, 'C')

def _safe(text):
    if not text:
        return ''
    return str(text).encode('latin-1', errors='replace').decode('latin-1')

def _section_header(pdf, title):
    pdf.set_fill_color(6, 16, 30)
    pdf.set_draw_color(0, 180, 220)
    pdf.set_font('Arial', 'B', 11)
    pdf.set_text_color(0, 210, 255)
    pdf.cell(0, 9, f'  {title}', 'LB', 1, 'L', True)
    pdf.set_draw_color(0, 80, 120)
    pdf.ln(2)

def generate_pdf_bytes(data, report_id=0):
    now = datetime.datetime.now()
    ref_num = f"AWR-{now.year}-{report_id:04d}"
    _months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    report_date = f"{now.day:02d} {_months[now.month-1]} {now.year}"

    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=25)

    # ── REPORT IDENTITY BANNER ──────────────────────────────
    pdf.set_fill_color(5, 12, 24)
    pdf.rect(10, pdf.get_y(), 190, 30, 'F')
    y0 = pdf.get_y() + 4

    pdf.set_xy(15, y0)
    pdf.set_font('Arial', 'B', 8)
    pdf.set_text_color(180, 140, 0)
    pdf.cell(55, 5, 'REPORT REFERENCE', 0, 0)

    pdf.set_xy(80, y0)
    pdf.set_font('Arial', 'B', 8)
    pdf.set_text_color(120, 120, 160)
    pdf.cell(40, 5, 'CLASSIFICATION', 0, 0)

    pdf.set_xy(140, y0)
    pdf.set_font('Arial', 'B', 8)
    pdf.set_text_color(120, 120, 160)
    pdf.cell(40, 5, 'ISSUE DATE', 0, 0)

    pdf.set_xy(15, y0 + 7)
    pdf.set_font('Arial', 'B', 14)
    pdf.set_text_color(255, 195, 0)
    pdf.cell(55, 8, ref_num, 0, 0)

    pdf.set_xy(80, y0 + 7)
    pdf.set_font('Arial', 'B', 11)
    pdf.set_text_color(255, 70, 70)
    pdf.cell(50, 8, 'CONFIDENTIAL', 0, 0)

    pdf.set_xy(140, y0 + 7)
    pdf.set_font('Arial', 'B', 10)
    pdf.set_text_color(180, 200, 220)
    pdf.cell(55, 8, report_date, 0, 0)

    pdf.set_y(y0 + 34)

    # ── EXECUTIVE SUMMARY ──────────────────────────────────
    _section_header(pdf, 'EXECUTIVE SUMMARY')
    dbms  = _safe(data.get('dbms', 'Unknown'))
    param = _safe(data.get('param', 'N/A'))
    tables = data.get('tables', {})
    total_rows = sum(len(i.get('rows', [])) for i in tables.values())
    risk = 'CRITICAL' if tables else 'HIGH'

    summary_lines = [
        f'This security assessment identified an active SQL Injection vulnerability in the target application.',
        f'Database Engine : {dbms}',
        f'Vulnerable Param: {param}',
        f'Tables Exposed  : {len(tables)}   |   Records Extracted: {total_rows}   |   Risk Level: {risk}',
        f'Assessment Date : {report_date}   |   Reference: {ref_num}',
    ]
    pdf.set_font('Arial', '', 10)
    for i, line in enumerate(summary_lines):
        if i == 0:
            pdf.set_text_color(200, 200, 200)
        elif ':' in line:
            pdf.set_text_color(160, 200, 255)
        else:
            pdf.set_text_color(200, 200, 200)
        pdf.cell(0, 7, line, 0, 1)
    pdf.ln(4)

    # ── SCAN DETAILS ───────────────────────────────────────
    _section_header(pdf, 'SCAN DETAILS')
    details = [
        ('Database System', dbms, (255, 200, 0)),
        ('Vulnerable Parameter', param, (255, 100, 100)),
        ('Tables Discovered', str(len(tables)), (0, 210, 255)),
        ('Total Records Found', str(total_rows), (0, 210, 255)),
        ('Risk Level', risk, (255, 70, 70) if risk == 'CRITICAL' else (255, 160, 0)),
    ]
    for label, value, color in details:
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(160, 170, 190)
        pdf.cell(65, 8, label + ':', 0, 0)
        pdf.set_font('Arial', 'B', 10)
        pdf.set_text_color(*color)
        pdf.cell(0, 8, value, 0, 1)
    pdf.ln(4)

    # ── EXTRACTED DATA ─────────────────────────────────────
    if tables:
        _section_header(pdf, f'EXTRACTED DATA  ({len(tables)} TABLE(S) COMPROMISED)')
        for tbl, info in tables.items():
            pdf.set_fill_color(20, 40, 65)
            pdf.set_font('Arial', 'B', 10)
            pdf.set_text_color(160, 120, 255)
            pdf.cell(0, 8, f'  Table: {_safe(tbl)}', 1, 1, 'L', True)

            cols = info.get('columns', [])
            rows = info.get('rows', [])
            if not cols:
                pdf.ln(2)
                continue

            num_cols = max(len(cols), 1)
            col_w = min(57, int(180 / num_cols))

            pdf.set_fill_color(8, 22, 40)
            pdf.set_font('Arial', 'B', 8)
            pdf.set_text_color(0, 190, 230)
            for col in cols[:3]:
                pdf.cell(col_w, 7, _safe(col).upper(), 1, 0, 'C', True)
            pdf.ln()

            pdf.set_font('Arial', '', 8)
            for i, row in enumerate(rows):
                pdf.set_fill_color(12, 26, 44) if i % 2 == 0 else pdf.set_fill_color(16, 33, 54)
                pdf.set_text_color(190, 210, 230)
                for val in list(row.values())[:3]:
                    pdf.cell(col_w, 7, _safe(str(val))[:28], 1, 0, 'C', True)
                pdf.ln()
            pdf.ln(5)

    # ── RECOMMENDATIONS ────────────────────────────────────
    _section_header(pdf, 'REMEDIATION RECOMMENDATIONS')
    dbms_lower = data.get('dbms', '').lower()
    if 'mysql' in dbms_lower:
        recs = [
            '1. Replace all dynamic queries with mysqli_prepare() / PDO prepared statements.',
            '2. Enable MySQL strict mode and audit logging.',
            '3. Apply Least Privilege - restrict DB user to SELECT only where possible.',
            '4. Deploy a Web Application Firewall (e.g. ModSecurity, Cloudflare WAF).',
            '5. Rotate all database credentials immediately.',
        ]
    elif 'sqlite' in dbms_lower:
        recs = [
            '1. Use PDO with prepared statements for all SQLite interactions.',
            '2. Move SQLite file outside the web root directory.',
            '3. Set file permissions to 600 and restrict web server access.',
            '4. Filter and escape all user-supplied inputs server-side.',
            '5. Consider migrating to a more hardened RDBMS for production use.',
        ]
    elif 'postgres' in dbms_lower or 'pg' in dbms_lower:
        recs = [
            '1. Use parameterized queries via psycopg2 or SQLAlchemy ORM.',
            '2. Enable pg_audit extension for query-level logging.',
            '3. Apply row-level security (RLS) policies.',
            '4. Rotate compromised credentials and revoke excess privileges.',
            '5. Schedule quarterly VAPT assessments.',
        ]
    else:
        recs = [
            '1. Use Parameterized Queries / Prepared Statements for all DB interactions.',
            '2. Sanitize and validate all user inputs on the server side.',
            '3. Apply Least Privilege principle to all database accounts.',
            '4. Enable a Web Application Firewall (WAF).',
            '5. Conduct periodic VAPT assessments (recommended: every 6 months).',
        ]

    pdf.set_font('Arial', '', 10)
    for rec in recs:
        pdf.set_text_color(160, 220, 160)
        pdf.cell(0, 7, rec, 0, 1)
    pdf.ln(6)

    # ── AUTHORISED SIGNATURE ───────────────────────────────
    pdf.set_fill_color(5, 14, 26)
    pdf.set_draw_color(100, 80, 0)
    sig_y = pdf.get_y()
    pdf.rect(10, sig_y, 190, 32, 'DF')
    pdf.set_xy(15, sig_y + 4)
    pdf.set_font('Arial', 'B', 9)
    pdf.set_text_color(180, 140, 0)
    pdf.cell(0, 6, 'DIGITALLY AUTHORISED BY:', 0, 1)
    pdf.set_x(15)
    pdf.set_font('Arial', 'B', 13)
    pdf.set_text_color(255, 200, 0)
    pdf.cell(0, 7, 'AWR Security Labs :: Security Director', 0, 1)
    pdf.set_x(15)
    pdf.set_font('Arial', 'I', 8)
    pdf.set_text_color(120, 130, 150)
    pdf.cell(0, 5, f'Issued: {report_date}  |  Ref: {ref_num}  |  Contact: +967775113425', 0, 1)
    pdf.set_x(15)
    pdf.set_font('Arial', '', 8)
    pdf.set_text_color(80, 90, 110)
    pdf.cell(0, 5, 'This report is CONFIDENTIAL. Authorized recipient use only. Unauthorized distribution is prohibited.', 0, 1)

    return pdf.output(dest='S').encode('latin-1')

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed = generate_password_hash(password)
        conn = sqlite3.connect('awr.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email, created_at) VALUES (?, ?, ?, ?)",
                      (username, hashed, email, datetime.datetime.now().isoformat()))
            conn.commit()
            flash('تم التسجيل بنجاح!', 'success')
            send_telegram(
                f"🆕 <b>مستخدم جديد سجّل!</b>\n"
                f"👤 الاسم: <code>{username}</code>\n"
                f"📧 البريد: <code>{email}</code>\n"
                f"🌐 IP: <code>{request.remote_addr}</code>\n"
                f"🕐 الوقت: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                f"⚡ انتظر تواصله للدفع وتفعيل حسابه!"
            )
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('اسم المستخدم موجود مسبقاً', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('awr.db')
        c = conn.cursor()
        c.execute("SELECT id, password, is_paid, is_admin FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            session['is_paid'] = bool(user[2])
            session['is_admin'] = bool(user[3])
            log_action('login', f'User {username} logged in', request.remote_addr)
            send_telegram(
                f"🔑 <b>تسجيل دخول</b>\n"
                f"👤 المستخدم: <code>{username}</code>\n"
                f"💳 مفعّل: {'✅ نعم' if user[2] else '❌ لا (لم يدفع بعد)'}\n"
                f"🌐 IP: <code>{request.remote_addr}</code>\n"
                f"🕐 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            flash('تم تسجيل الدخول بنجاح!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('بيانات الدخول غير صحيحة', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('تم تسجيل الخروج', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT id, filename, dbms, created_at FROM reports WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    reports = c.fetchall()
    c.execute("SELECT COUNT(*) FROM reports WHERE user_id = ?", (session['user_id'],))
    count = c.fetchone()[0]
    c.execute("SELECT is_paid FROM users WHERE id = ?", (session['user_id'],))
    row = c.fetchone()
    conn.close()
    is_paid = bool(row[0]) if row else False
    session['is_paid'] = is_paid
    return render_template('dashboard.html', reports=reports, count=count, is_paid=is_paid)

@app.route('/upload', methods=['POST'])
@payment_required
def upload_file():
    if 'logfile' not in request.files:
        flash('لم يتم اختيار ملف', 'danger')
        return redirect(url_for('dashboard'))
    files = request.files.getlist('logfile')
    if not files or files[0].filename == '':
        flash('لم يتم اختيار أي ملف', 'danger')
        return redirect(url_for('dashboard'))
    for file in files:
        if file and file.filename.endswith(('.log', '.txt')):
            content = file.read().decode('utf-8', errors='ignore')
            parser = SQLiLogParser(content)
            parser.save_report(session['user_id'], file.filename)
            log_action('upload', f'User {session["username"]} uploaded {file.filename}', request.remote_addr)
            send_telegram(
                f"📤 <b>ملف جديد رُفع!</b>\n"
                f"👤 المستخدم: <code>{session['username']}</code>\n"
                f"📁 الملف: <code>{file.filename}</code>\n"
                f"🗄️ DBMS: <code>{parser.data.get('dbms','Unknown')}</code>\n"
                f"📊 جداول: {len(parser.data.get('tables',{}))}\n"
                f"🕐 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            flash(f'تم تحليل الملف {file.filename} بنجاح', 'success')
        else:
            flash(f'الملف {file.filename} غير مدعوم', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/download/<int:report_id>')
@payment_required
def download_report(report_id):
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT data, dbms FROM reports WHERE id = ? AND user_id = ?", (report_id, session['user_id']))
    report = c.fetchone()
    conn.close()
    if not report:
        flash('التقرير غير موجود', 'danger')
        return redirect(url_for('dashboard'))
    data = json.loads(report[0])
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        md = f"# تقرير أمني\nDBMS: {data['dbms']}\nParam: {data['param']}\n"
        for tbl, info in data.get('tables', {}).items():
            md += f"\n## {tbl}\n"
            for row in info.get('rows', []):
                md += " | ".join(row.values()) + "\n"
        zf.writestr('REPORT.md', md)
        zf.writestr('report.json', json.dumps(data, indent=2))
        tables_data = data.get('tables', {})
        all_cols = set()
        for info in tables_data.values():
            all_cols.update(info.get('columns', []))
        all_cols = sorted(all_cols) or ['id', 'username', 'password']
        csv_lines = ['table,' + ','.join(all_cols)]
        for tbl, info in tables_data.items():
            cols = info.get('columns', all_cols)
            for row in info.get('rows', []):
                vals = [str(row.get(col, '')) for col in all_cols]
                csv_lines.append(f"{tbl}," + ','.join(vals))
        if len(csv_lines) == 1:
            csv_lines.append('N/A,No data extracted from this log file')
        csv_data = '\n'.join(csv_lines) + '\n'
        zf.writestr('extracted_creds.csv', csv_data)
        pdf_bytes = generate_pdf_bytes(data, report_id)
        zf.writestr(f'report_{report_id}.pdf', pdf_bytes)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=f'report_{report_id}.zip', mimetype='application/zip')

@app.route('/activate-whatsapp')
@login_required
def activate_whatsapp():
    phone = '+967775113425'
    uname = session.get('username', '')
    msg = f'أريد تفعيل حسابي في AWR Security Labs — اسم المستخدم: {uname}'
    log_action('activation_request', f'User {uname} requested activation', request.remote_addr)
    send_telegram(
        f"💳 <b>طلب تفعيل حساب!</b>\n"
        f"👤 المستخدم: <code>{uname}</code>\n"
        f"🌐 IP: <code>{request.remote_addr}</code>\n"
        f"🕐 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
        f"⚡ <b>تحقق من الدفع وفعّل حسابه من لوحة الأدمن!</b>"
    )
    return redirect(f'https://wa.me/{phone}?text={msg}')

@app.route('/admin')
@admin_required
def admin_panel():
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, is_paid, is_admin, created_at FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    c.execute("SELECT COUNT(*) FROM reports")
    total_reports = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE is_paid = 1")
    paid_count = c.fetchone()[0]
    c.execute("SELECT action, details, ip, created_at FROM logs ORDER BY created_at DESC LIMIT 50")
    audit_logs = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, total_reports=total_reports,
                           paid_count=paid_count, audit_logs=audit_logs)

@app.route('/admin/toggle-paid/<int:user_id>', methods=['POST'])
@admin_required
def toggle_paid(user_id):
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT username, is_paid FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        new_status = 0 if row[1] else 1
        c.execute("UPDATE users SET is_paid = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        action = 'تفعيل' if new_status else 'إلغاء تفعيل'
        log_action('admin_toggle', f'Admin {action} user {row[0]}', request.remote_addr)
        send_telegram(
            f"🛡️ <b>تم {action} حساب</b>\n"
            f"👤 المستخدم: <code>{row[0]}</code>\n"
            f"{'✅ يستطيع الآن الرفع والتحميل' if new_status else '🔒 تم إيقاف وصوله'}"
        )
        flash(f'✅ تم {action} حساب {row[0]}', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle-admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    if user_id == session.get('user_id'):
        flash('لا يمكنك تغيير صلاحيات حسابك الخاص', 'danger')
        return redirect(url_for('admin_panel'))
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT username, is_admin FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        new_status = 0 if row[1] else 1
        c.execute("UPDATE users SET is_admin = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
        log_action('admin_toggle', f'Admin toggled admin status for {row[0]}', request.remote_addr)
        flash(f'✅ تم تحديث صلاحيات {row[0]}', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('لا يمكنك حذف حسابك الخاص', 'danger')
        return redirect(url_for('admin_panel'))
    conn = sqlite3.connect('awr.db')
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        c.execute("DELETE FROM reports WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        log_action('admin_delete', f'Admin deleted user {row[0]}', request.remote_addr)
        flash(f'🗑️ تم حذف المستخدم {row[0]}', 'success')
    conn.close()
    return redirect(url_for('admin_panel'))

@app.route('/whatsapp')
def whatsapp():
    phone = '+967775113425'
    msg = 'أريد خدمة اختبار اختراق'
    return redirect(f'https://wa.me/{phone}?text={msg}')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/google2b6e64c6ea7510e2.html')
def google_verify():
    return send_from_directory('.', 'google2b6e64c6ea7510e2.html', mimetype='text/html')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('.', 'sitemap.xml')

@app.route('/robots.txt')
def robots():
    return send_from_directory('static', 'robots.txt')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
