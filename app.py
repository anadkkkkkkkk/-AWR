from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for
import os, sys, zipfile, io, re, json, csv
from datetime import datetime
import base64, requests, subprocess
from functools import wraps

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.secret_key = os.urandom(24)  # مفتاح التشفير للجلسات

# ========== إعدادات المصادقة ==========
# كلمة المرور الافتراضية (يمكن تغييرها عبر متغير البيئة)
DEFAULT_PASSWORD = "admin123"
APP_PASSWORD = os.environ.get("APP_PASSWORD", DEFAULT_PASSWORD)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# دالة التحقق من تسجيل الدخول
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ========== تضمين كود الأداة ==========
CONSULTANT_NAME = "AWR Security Labs"
WHATSAPP_CONTACT = "+967775113425"

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
        if "sqlite" in dbms: return ["1. استخدام Prepared Statements مع PDO.", "2. فلترة المدخلات.", "3. تقليل صلاحيات قاعدة البيانات."]
        elif "mysql" in dbms: return ["1. استخدام mysqli_prepare().", "2. تفعيل WAF.", "3. تطبيق Least Privilege."]
        else: return ["1. استخدام Parameterized Queries.", "2. تنقية المدخلات.", "3. إجراء VAPT دوري."]

    def generate_zip(self):
        out_dir = "temp_report"
        os.makedirs(out_dir, exist_ok=True)
        md_path = f"{out_dir}/REPORT.md"
        json_path = f"{out_dir}/report.json"
        csv_path = f"{out_dir}/extracted_creds.csv"

        with open(md_path, "w", encoding='utf-8') as f:
            f.write(f"# 🔒 تقرير تقييم أمني - AWR Security Labs\n")
            f.write(f"**للتواصل (واتساب):** {WHATSAPP_CONTACT}\n")
            f.write(f"**التاريخ:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**سعر التقرير: ١٠٠ دولار أمريكي**\n---\n")
            f.write(f"**DBMS:** {self.data['dbms']}\n**Param:** {self.data['param']}\n\n")
            for tbl, info in self.data["tables"].items():
                f.write(f"### جدول: {tbl}\n")
                f.write("| " + " | ".join(info['columns']) + " |\n|" + "---|" * len(info['columns']) + "\n")
                for row in info['rows']:
                    f.write("| " + " | ".join(row.values()) + " |\n")
                f.write("\n")
            f.write("## التوصيات\n")
            for rec in self.generate_recommendations():
                f.write(f"- {rec}\n")
            f.write("\n---\n*تم التوقيع بواسطة AWR Security Labs*")

        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

        all_rows = []
        for tbl, info in self.data["tables"].items():
            for row in info['rows']:
                rd = {"table": tbl}; rd.update(row); all_rows.append(rd)
        if all_rows:
            with open(csv_path, "w", newline="", encoding='utf-8') as csvfile:
                w = csv.DictWriter(csvfile, fieldnames=["table"] + list(all_rows[0].keys() if all_rows else []))
                w.writeheader(); w.writerows(all_rows)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
            for file_name in os.listdir(out_dir):
                zip_file.write(os.path.join(out_dir, file_name), file_name)
        zip_buffer.seek(0)
        return zip_buffer

# ========== Routes ==========
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form.get('password')
        if password == APP_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="كلمة المرور غير صحيحة")
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'logfile' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['logfile']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    try:
        content = file.read().decode('utf-8', errors='ignore')
        parser = SQLiLogParser(content)
        zip_data = parser.generate_zip()
        return send_file(zip_data, as_attachment=True, download_name='report.zip', mimetype='application/zip')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
