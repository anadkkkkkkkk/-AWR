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
