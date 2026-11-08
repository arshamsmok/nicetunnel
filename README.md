# NiceTunnel (نایس تانل)

ساخته‌شده توسط **Arsham Smoke** (آرشام اسموک) · لایسنس MIT

تونل TCP معکوس بین دو سرور (مثلاً ایران و خارج) با منوی تعاملی. روی هر دو سرور با یک دستور نصب می‌شود.

```
کاربر ──► سرور ایران ◄══ تونل ══ سرور خارج ──► سرویس روی سرور خارج
```

- سرور خارج خودش به سرور ایران وصل می‌شود، پس فقط سرور ایران به پورت ورودی باز نیاز دارد.
- احراز هویت با توکن مشترک (HMAC)، اتصال مجدد خودکار، اجرا به صورت سرویس systemd (بعد از ریبوت خودش بالا می‌آید).
- چند تونل مستقل با slot از ۱ تا ۱۰، فوروارد چند پورت، و بهینه‌سازی BBR از داخل منو.
- تونل ترافیک را رمز نمی‌کند. روی آن پروتکل‌هایی را عبور بدهید که خودشان رمزنگاری دارند (TLS، VLESS، Trojan، SSH و مانند آن).

## ۱. گذاشتن سورس روی GitHub

۱. در github.com وارد حسابتان شوید (اگر حساب ندارید، Sign up).

۲. دکمه **+** بالای صفحه ← **New repository**:
   - Repository name: `nicetunnel`
   - حتماً **Public** را انتخاب کنید (برای ریپوی Private لینک raw بدون توکن کار نمی‌کند)
   - **Create repository**

۳. در صفحه ریپوی خالی روی لینک **uploading an existing file** بزنید، پنج فایل `install.sh`، `nicetunnel.sh`، `nicetunnel.py`، `README.md` و `LICENSE` را بکشید و رها کنید، بعد **Commit changes**.

۴. روی `install.sh` کلیک کنید ← آیکون مداد (Edit) ← در بالای فایل خط زیر را پیدا کنید و `YOUR_GITHUB_USERNAME` را با یوزرنیم GitHub خودتان عوض کنید:

   ```bash
   GITHUB_USER="YOUR_GITHUB_USERNAME"
   ```

   بعد **Commit changes**.

۵. لینک دانلود (raw) شما این است:

   ```
   https://raw.githubusercontent.com/یوزرنیم_شما/nicetunnel/main/install.sh
   ```

   آن را در مرورگر باز کنید. باید متن اسکریپت را ببینید، نه صفحه خطا.

## ۲. نصب روی هر دو سرور

با `ssh root@IP` وارد سرور شوید (مستقیم با root، چون `sudo` با این دستور کار نمی‌کند؛ اگر یوزر root نیستید اول `sudo -i` بزنید)، بعد:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/یوزرنیم_شما/nicetunnel/main/install.sh)
```

نصب انجام می‌شود و منو باز می‌شود. بعداً هر وقت خواستید منو را باز کنید:

```bash
nicetunnel
```

## ۳. ساخت تونل از داخل منو

۱. روی **سرور ایران**: `1) Create tunnel` ← `1) Iran server` ← slot (Enter برای پیش‌فرض) ← bridge port (پیش‌فرض 7000) ← پورت‌های عمومی (مثلاً `443`) ← توکن (Enter تا خودش بسازد). توکن را کپی کنید.

۲. روی **سرور خارج**: `1) Create tunnel` ← `2) Foreign server` ← همان slot و همان bridge port ← آی‌پی سرور ایران ← همان توکن ← Enter.

۳. در منو وضعیت هر دو باید `active` باشد. `Manage tunnels` ← slot ← `Logs` برای دیدن لاگ.

مثال پورت‌ها: `443` یعنی کاربر به 443 ایران وصل شود و به 443 سرور خارج برسد. `8443:8080` یعنی به 8443 ایران وصل شود و به 8080 سرور خارج برسد.

پورت bridge و پورت‌های عمومی باید در فایروال سرور ایران (و پنل فایروال دیتاسنتر، اگر دارد) باز باشند. اگر `ufw` روشن باشد، منو خودش پیشنهاد باز کردنشان را می‌دهد.

## اگر سرور به GitHub دسترسی نداشت

چهار فایل را با scp به سرور بفرستید و کنار هم اجرا کنید:

```bash
scp install.sh nicetunnel.sh nicetunnel.py root@IP:/root/
ssh root@IP
bash install.sh
```

اگر فایل‌های `nicetunnel.py` و `nicetunnel.sh` کنار `install.sh` باشند، چیزی دانلود نمی‌شود.

## بروزرسانی

فایل‌های جدید را در GitHub جایگزین کنید (Add file ← Upload files)، بعد روی هر سرور `nicetunnel` ← `4) Update from GitHub`. تونل‌ها خودکار ری‌استارت می‌شوند.

## حذف

`nicetunnel` ← `5) Uninstall`

## اجرای دستی بدون منو (برای تست)

```bash
export NICETUNNEL_TOKEN=یک_رشته_حداقل_۱۶_کاراکتری
python3 nicetunnel.py server --bridge 7000 --ports 443       # سرور ایران
python3 nicetunnel.py client --server IP_IRAN --bridge 7000  # سرور خارج
```
