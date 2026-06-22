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
        created_at TEXT
    )''')
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
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'AWR Security Labs - تقرير أمني', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'الصفحة {self.page_no()} | +967775113425', 0, 0, 'C')

def generate_pdf(data, filename):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 10, f"DBMS: {data.get('dbms', 'Unknown')}", 0, 1)
    pdf.cell(0, 10, f"Parameter: {data.get('param', 'N/A')}", 0, 1)
    pdf.ln(5)
    for tbl, info in data.get('tables', {}).items():
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 10, f"Table: {tbl}", 0, 1)
        pdf.set_font('Arial', '', 10)
        cols = info.get('columns', [])
        if cols:
            col_line = " | ".join(cols)
            pdf.cell(0, 10, col_line, 0, 1)
            pdf.cell(0, 5, "-" * 40, 0, 1)
        for row in info.get('rows', []):
            row_line = " | ".join(row.values())
            pdf.cell(0, 8, row_line, 0, 1)
        pdf.ln(5)
    pdf.output(filename)

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
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
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
    conn.close()
    return render_template('dashboard.html', reports=reports, count=count)

@app.route('/upload', methods=['POST'])
@login_required
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
@login_required
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
        csv_data = "table,id,username,password\n"
        for tbl, info in data.get('tables', {}).items():
            for row in info.get('rows', []):
                csv_data += f"{tbl},{row.get('id','')},{row.get('username','')},{row.get('password','')}\n"
        zf.writestr('extracted_creds.csv', csv_data)
        pdf_filename = f'report_{report_id}.pdf'
        generate_pdf(data, pdf_filename)
        zf.write(pdf_filename)
        os.remove(pdf_filename)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name=f'report_{report_id}.zip', mimetype='application/zip')

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug)
