روی هر VPS (اوبونتو 22)

بدون کلون/کپی، مستقیم از گیت‌هاب اجرا کن:

curl -fsSL https://raw.githubusercontent.com/vahid162/ip-health-check/main/vps_iptest.sh | sudo bash -s -- start


این یک خط همه‌چیز را بالا می‌آورد، پورت‌ها را باز می‌کند و گزارش می‌سازد. (اگر «getcwd» خطا دیدی، اول cd /root بزن و دوباره همین دستور را اجرا کن.)

می‌توانی برای توقف هم بگویی:
curl -fsSL https://raw.githubusercontent.com/vahid162/ip-health-check/main/vps_iptest.sh | sudo bash -s -- stop

روی ویندوز (PowerShell)

یا ریپو را کلون کن یا فایل را دانلود کن، بعد:
cd C:\ip-health-check   # به پوشه‌ای که ip_health_client.ps1 داخلش است برو
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\ip_health_client.ps1

(ExecutionPolicy را فقط برای همان پنجره باز می‌گذاریم؛ توصیهٔ رسمی هم همین است که محدوده را به Session محدود کنی.)
