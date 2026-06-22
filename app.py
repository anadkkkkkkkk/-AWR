import os, re, json, csv, sqlite3, hashlib, io, zipfile, base64, requests, datetime
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

def generate_pdf_bytes(data):
    pdf = PDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    pdf.set_fill_color(10, 20, 35)
    pdf.set_draw_color(0, 80, 120)

    pdf.set_font('Arial', 'B', 13)
    pdf.set_text_color(0, 210, 255)
    pdf.cell(0, 8, 'SCAN SUMMARY', 0, 1)
    pdf.set_draw_color(0, 210, 255)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)

    pdf.set_font('Arial', '', 11)
    pdf.set_text_color(220, 220, 220)
    pdf.cell(50, 8, 'Database System:', 0, 0)
    pdf.set_font('Arial', 'B', 11)
    pdf.set_text_color(255, 200, 0)
    pdf.cell(0, 8, _safe(data.get('dbms', 'Unknown')), 0, 1)

    pdf.set_font('Arial', '', 11)
    pdf.set_text_color(220, 220, 220)
    pdf.cell(50, 8, 'Vulnerable Parameter:', 0, 0)
    pdf.set_font('Arial', 'B', 11)
    pdf.set_text_color(255, 100, 100)
    pdf.cell(0, 8, _safe(data.get('param', 'N/A')), 0, 1)
    pdf.ln(6)

    tables = data.get('tables', {})
    if tables:
        pdf.set_font('Arial', 'B', 13)
        pdf.set_text_color(0, 210, 255)
        pdf.cell(0, 8, f'EXTRACTED DATA ({len(tables)} table(s) found)', 0, 1)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)

        for tbl, info in tables.items():
            pdf.set_fill_color(15, 30, 50)
            pdf.set_font('Arial', 'B', 11)
            pdf.set_text_color(124, 58, 237)
            pdf.cell(0, 8, f'  Table: {_safe(tbl)}', 1, 1, 'L', True)

            cols = info.get('columns', [])
            if cols:
                pdf.set_font('Arial', 'B', 9)
                pdf.set_text_color(180, 180, 180)
                pdf.set_fill_color(8, 20, 35)
                col_w = min(60, 180 // max(len(cols), 1))
                for col in cols:
                    pdf.cell(col_w, 7, _safe(col).upper(), 1, 0, 'C', True)
                pdf.ln()

            pdf.set_font('Arial', '', 9)
            for i, row in enumerate(info.get('rows', [])):
                pdf.set_fill_color(12, 25, 42) if i % 2 == 0 else pdf.set_fill_color(16, 32, 52)
                pdf.set_text_color(200, 200, 200)
                for val in row.values():
                    pdf.cell(col_w, 7, _safe(val), 1, 0, 'C', True)
                pdf.ln()
            pdf.ln(4)

    pdf.set_font('Arial', 'B', 13)
    pdf.set_text_color(0, 210, 255)
    pdf.cell(0, 8, 'RECOMMENDATIONS', 0, 1)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    recs_en = [
        '1. Use Parameterized Queries / Prepared Statements for all DB interactions.',
        '2. Sanitize and validate all user inputs on the server side.',
        '3. Apply Least Privilege principle to database accounts.',
        '4. Enable a Web Application Firewall (WAF).',
        '5. Conduct periodic VAPT assessments.',
    ]
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(180, 220, 180)
    for rec in recs_en:
        pdf.cell(0, 7, rec, 0, 1)
    pdf.ln(6)

    pdf.set_fill_color(4, 15, 25)
    pdf.set_draw_color(0, 80, 120)
    pdf.rect(10, pdf.get_y(), 190, 20, 'DF')
    pdf.set_font('Arial', 'B', 10)
    pdf.set_text_color(0, 210, 255)
    pdf.cell(0, 8, 'Contact: +967775113425  |  AWR Security Labs  |  CONFIDENTIAL', 0, 1, 'C')
    pdf.set_font('Arial', '', 8)
    pdf.set_text_color(100, 120, 140)
    pdf.cell(0, 6, 'This report is for authorized use only. Unauthorized distribution is prohibited.', 0, 1, 'C')

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
        pdf_bytes = generate_pdf_bytes(data)
        zf.writestr(f'report_{report_id}.pdf', pdf_bytes)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=f'report_{report_id}.zip', mimetype='application/zip')

@app.route('/activate-whatsapp')
@login_required
def activate_whatsapp():
    phone = '+967775113425'
    msg = f'أريد تفعيل حسابي في AWR Security Labs — اسم المستخدم: {session.get("username","")}'
    log_action('activation_request', f'User {session.get("username")} requested activation', request.remote_addr)
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
