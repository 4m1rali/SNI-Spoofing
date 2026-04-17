# NexNull — پروکسی دور زدن DPI

**جعل SNI پیشرفته از طریق دستکاری هدرهای TCP/IP با WinDivert**

> 🇮🇷 فارسی | 🇬🇧 [English](README.md)

---

## NexNull چیست؟

NexNull یک پروکسی دور زدن DPI برای ویندوز است که به کاربران ایران کمک می‌کند **سیستم‌های بازرسی عمیق بسته (DPI)** مورد استفاده اپراتورهای اینترنتی ایران را دور بزنند.

این ابزار با رهگیری TCP handshake در سطح کرنل توسط **WinDivert** کار می‌کند و یک TLS ClientHello جعلی با SNI جعلی به سمت یک دامنه مجاز تزریق می‌کند. سیستم DPI دامنه مجاز را می‌بیند و اتصال را تأیید می‌کند. سرور واقعی پکت خارج از پنجره را نادیده می‌گیرد. ترافیک واقعی آزادانه جریان پیدا می‌کند.

> بر پایه کار اصلی **[patterniha](https://github.com/patterniha/SNI-Spoofing)** — تمام احترام و اعتبار به سازنده اصلی.

---

## روش کار

۱. NexNull روی یک پورت محلی گوش می‌دهد (`LISTEN_PORT`)
۲. کلاینت به پروکسی متصل می‌شود
۳. پروکسی یک اتصال TCP خروجی به `CONNECT_IP:CONNECT_PORT` باز می‌کند
۴. WinDivert TCP handshake را در سطح کرنل رهگیری می‌کند
۵. بعد از ACK سه‌طرفه، NexNull یک TLS ClientHello جعلی تزریق می‌کند با:
   - SNI جعلی = `FAKE_SNI` (یک دامنه مجاز)
   - شماره sequence TCP عمداً اشتباه: `seq = (syn_seq + 1 - len(fake_data)) & 0xFFFFFFFF`
   - اثر انگشت مرورگر واقعی (Chrome / Firefox / Safari / Edge) با مقادیر GREASE
   - تایمینگ تزریق با توزیع گاوسی شبیه انسان
   - TTL تصادفی برای شبیه‌سازی یک هاست واقعی در فاصله شبکه
   - جیتر پدینگ (±۱۲ بایت) برای جلوگیری از اثرانگشت‌گیری بر اساس اندازه
۶. DPI SNI مجاز را می‌بیند و اتصال را تأیید می‌کند
۷. سرور واقعی پکت خارج از پنجره را نادیده می‌گیرد
۸. سرور پکت جعلی را ACK می‌کند — bypass تأیید شد
۹. رله دوطرفه کامل شروع می‌شود

**چرا شماره sequence اشتباه کار می‌کند؟**

سیستم‌های DPI **بازرسی سطحی یا stateless** انجام می‌دهند — اولین پکت داده را می‌خوانند و فیلد SNI را بررسی می‌کنند بدون اینکه شماره sequence TCP را کامل اعتبارسنجی کنند. سرور مقصد stateful است و پکت خارج از پنجره را به درستی رد می‌کند. DPI فریب می‌خورد، سرور تحت تأثیر قرار نمی‌گیرد.

---

## دیاگرام معماری

```
  کلاینت                  NexNull                   DPI            سرور مقصد
    |                         |                       |                  |
    |--- TCP connect -------->|                       |                  |
    |                         |--- SYN seq=X -------->|----------------->|
    |                         |<-- SYN-ACK seq=Y -----|<-----------------|
    |                         |--- ACK seq=X+1 ------>|----------------->|
    |                         |                       |                  |
    |                   [WinDivert تزریق]             |                  |
    |                         |--- PSH seq=X+1-N ---->|                  |
    |                         |   TLS ClientHello جعلی|  SNI=hcaptcha   |
    |                         |   SNI = FAKE_SNI       |  ALLOW! ✓       |
    |                         |   اثرانگشت مرورگر     |                  |
    |                         |   تایمینگ انسانی      |                  |
    |                         |   TTL جعلی             |                  |
    |                         |   (seq اشتباه، سرور   |                  |
    |                         |    نادیده می‌گیرد)     |                  |
    |                         |<-- ACK ack=X+1 --------|<-----------------|
    |                         |                       |                  |
    |<====== رله دوطرفه کامل ========================>|=================>|
```

---

## دیاگرام سطح پکت: روش bypass — `wrong_seq`

```
  کلاینت        NexNull              سیستم DPI         سرور مقصد
    |                |                    |                   |
    |--- اتصال ----->|                    |                   |
    |                |--- SYN seq=X ----->|------------------>|
    |                |<-- SYN-ACK seq=Y --|<------------------|
    |                |--- ACK seq=X+1 --->|------------------>|
    |                |                    |                   |
    |          [WinDivert تزریق می‌کند]   |                   |
    |                |--- PSH seq=X+1-N ->|                   |
    |                |  TLS ClientHello   | DPI می‌بیند SNI   |
    |                |  SNI = FAKE_SNI    | مجاز است ✓        |
    |                |  (seq اشتباه)      |                   |
    |                |  سرور نادیده می‌گیرد — خارج از پنجره  |
    |                |<-- ACK ack=X+1 ----|<------------------|
    |                |  bypass تأیید ✓    |                   |
    |<===== رله دوطرفه کامل ============>|==================>|
```

---

## ساختار پروژه

```
NexNull/
├── main.py                    # نقطه ورود — بررسی admin، بنر، حلقه accept
├── logger_setup.py            # لاگ ۲۵۶ رنگ، سطح VERBOSE، فیلتر WinError 6
├── facts.py                   # ۶۳ حقیقت جالب درباره فایروال ایران (Nex-chan)
├── config.json                # تنظیمات اجرا
├── main.spec                  # اسپک بیلد PyInstaller
├── requirements.txt           # وابستگی‌های Python
│
├── core/
│   ├── config.py              # Config dataclass + بارگذاری + اعتبارسنجی
│   ├── connection.py          # MonitorConnection — ردیاب وضعیت sequence TCP
│   ├── relay.py               # رله async، rate limiting، idle timeout، لاگ SNI
│   └── stats.py               # آمار، شمارنده per-SNI، آپدیت title bar
│
├── bypass/
│   ├── injector.py            # کلاس پایه WinDivert + اتصال مجدد خودکار با backoff
│   └── fake_tcp.py            # bypass wrong_seq، تایمینگ انسانی، جعل TTL
│
└── utils/
    ├── network_tools.py       # تشخیص IP اینترفیس محلی
    ├── packet_templates.py    # سازنده TLS ClientHello با پروفایل مرورگر
    ├── fingerprint.py         # پروفایل‌های اثرانگشت TLS مرورگر (Chrome/Firefox/Safari/Edge)
    ├── humanize.py            # مدل تایمینگ انسانی (جیتر گاوسی + Weibull)
    └── sni_extractor.py       # پارسر SNI از TLS، آگاه از fragmentation، پشتیبانی IDN
```

---

## پیش‌نیازها

- ویندوز ۱۰ / ۱۱ (64 بیتی)
- دسترسی Administrator (WinDivert نیاز به دسترسی سطح کرنل دارد)
- Python 3.11 به بالا (برای اجرا از سورس)
- `pydivert` (در فایل `.exe` آماده بسته‌بندی شده)

---

## نصب و راه‌اندازی

### روش الف — اجرای فایل `.exe` آماده

۱. فایل `main.exe` را دانلود کنید
۲. فایل `config.json` را در **همان پوشه** کنار `main.exe` قرار دهید
۳. روی `main.exe` راست‌کلیک کنید ← **Run as administrator**

### روش ب — اجرا از سورس

```bash
pip install -r requirements.txt
python main.py
```

> باید به عنوان Administrator اجرا شود.

### بیلد گرفتن از سورس

```bash
pip install pyinstaller
python -m PyInstaller main.spec
```

خروجی در `dist\main.exe` — فایل `config.json` را کنارش کپی کنید.

---

## تنظیمات (`config.json`)

```json
{
  "LISTEN_HOST":      "0.0.0.0",
  "LISTEN_PORT":      40443,
  "CONNECT_IP":       "104.19.229.21",
  "CONNECT_PORT":     443,
  "FAKE_SNI":         "hcaptcha.com",

  "BYPASS_TIMEOUT":   2.0,
  "FAKE_DELAY_MS":    1.0,
  "CONNECT_TIMEOUT":  5.0,

  "RECV_BUFFER":      65536,
  "MAX_CONNECTIONS":  0,
  "IDLE_TIMEOUT":     120,
  "RATE_LIMIT":       0,

  "BROWSER_PROFILE":  "random",
  "TTL_SPOOF":        true,

  "LOG_LEVEL":        "INFO",
  "LOG_CLIENT_SNI":   true,
  "LOG_FILE":         "",
  "STATS_INTERVAL":   60
}
```

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `LISTEN_HOST` | `"0.0.0.0"` | آدرس محلی برای گوش دادن (`0.0.0.0` = همه اینترفیس‌ها) |
| `LISTEN_PORT` | `40443` | پورت محلی پروکسی |
| `CONNECT_IP` | — | IP سرور مقصد |
| `CONNECT_PORT` | `443` | پورت سرور مقصد (معمولاً ۴۴۳) |
| `FAKE_SNI` | `"hcaptcha.com"` | دامنه جعلی برای فریب DPI — باید فیلتر نشده باشد |
| `BYPASS_TIMEOUT` | `2.0` | ثانیه‌های انتظار برای تکمیل bypass handshake |
| `FAKE_DELAY_MS` | `1.0` | تأخیر پایه (میلی‌ثانیه) قبل از تزریق پکت جعلی — با جیتر گاوسی انسانی‌سازی می‌شود |
| `CONNECT_TIMEOUT` | `5.0` | timeout اتصال TCP به ثانیه |
| `RECV_BUFFER` | `65536` | بایت در هر فراخوانی `recv()` |
| `MAX_CONNECTIONS` | `0` | حداکثر اتصال همزمان — `0` = نامحدود |
| `IDLE_TIMEOUT` | `120` | ثانیه‌های بی‌فعالیت رله قبل از بستن — `0` = غیرفعال |
| `RATE_LIMIT` | `0` | حداکثر اتصال جدید در ثانیه به ازای هر IP — `0` = غیرفعال |
| `BROWSER_PROFILE` | `"random"` | پروفایل اثرانگشت TLS: `chrome` / `firefox` / `safari` / `edge` / `random` |
| `TTL_SPOOF` | `true` | تصادفی‌سازی TTL پکت جعلی برای شبیه‌سازی هاست واقعی در فاصله شبکه |
| `LOG_LEVEL` | `"INFO"` | سطح لاگ: `DEBUG` / `VERBOSE` / `INFO` / `WARNING` / `ERROR` |
| `LOG_CLIENT_SNI` | `true` | لاگ کردن SNI واقعی از TLS hello کلاینت |
| `LOG_FILE` | `""` | مسیر فایل لاگ متنی — خالی = غیرفعال |
| `STATS_INTERVAL` | `60` | ثانیه‌های بین ورودی‌های خودکار لاگ آمار — `0` = غیرفعال |

---

## سطوح لاگ

| سطح | نشانه | چه چیزی لاگ می‌شود |
|---|---|---|
| `DEBUG` | `[.]` | تمام جزئیات سطح پکت، عملیات سوکت، انتقال‌های وضعیت |
| `VERBOSE` | `[>]` | جزئیات سطح اتصال بین DEBUG و INFO |
| `INFO` | `[+]` | باز/بسته شدن اتصال، SNI، شروع/توقف رله، آمار — **توصیه شده** |
| `WARNING` | `[!]` | اتصال‌های ناموفق، شکست bypass، برخورد با rate limit |
| `ERROR` | `[x]` | خطاهای جدی |
| `CRITICAL` | `[!!]` | خطاهای مرگبار |

---

## فرمت لاگ

```
[08:15:05] [+]   [INFO    ] [relay]    CONN  127.0.0.1:52100  [active=3  total=47]
[08:15:05] [+]   [INFO    ] [relay]    SNI  example.com                        from 127.0.0.1
[08:15:05] [.]   [DEBUG   ] [fake_tcp] Using browser profile: Chrome/124
[08:15:05] [.]   [DEBUG   ] [fake_tcp] Fake injected  192.168.1.5:52101 -> 104.19.229.21:443  ttl=56
[08:15:05] [+]   [INFO    ] [relay]    RELAY 127.0.0.1:52100  <->  104.19.229.21:443
[08:15:05] [+]   [INFO    ] [relay]    CLOSE 127.0.0.1:52100
[08:15:05] [+]   [INFO    ] [stats]    Stats  uptime: 5m 23s    total: 47     active: 3  ...
[08:15:05] [+]   [INFO    ] [stats]    Top SNIs: example.com(23)  google.com(12)  ...
```

---

## نوار عنوان (Title Bar)

نوار عنوان کنسول ویندوز هر ۲ ثانیه با آمار زنده آپدیت می‌شود:

```
NexNull  |  Req: 47  Active: 3  Failed: 2  Up: 12.3MB  Dn: 45.6MB  5m 23s
```

---

## جزئیات فنی

### اثرانگشت TLS مرورگر (`utils/fingerprint.py`)

NexNull ClientHello‌های جعلی می‌سازد که با اثرانگشت TLS مرورگرهای واقعی مطابقت دارند:

| پروفایل | ترتیب Cipher Suite | ترتیب Extension | GREASE | ALPN |
|---|---|---|---|---|
| `chrome` | Chrome 124 | Chrome 124 | بله | h2, http/1.1 |
| `firefox` | Firefox 125 | Firefox 125 | خیر | h2, http/1.1 |
| `safari` | Safari 17 | Safari 17 | خیر | h2, http/1.1 |
| `edge` | Edge 124 | Edge 124 | بله | h2, http/1.1 |
| `random` | هر اتصال مرورگر متفاوت | — | — | — |

**مقادیر GREASE** (RFC 8701) در cipher suites و extensions تزریق می‌شوند — دقیقاً همان کاری که Chrome و Edge انجام می‌دهند تا مطمئن شوند سیستم‌های DPI مقادیر ناشناخته را نادیده می‌گیرند.

---

### تایمینگ شبیه انسان (`utils/humanize.py`)

تأخیر تزریق پکت جعلی یک `sleep(1ms)` ثابت نیست. از این مدل استفاده می‌کند:

- **مؤلفه گاوسی**: مرکز روی `FAKE_DELAY_MS`، σ = ۳۰٪ — مدل‌سازی زمان پردازش TLS stack
- **دنباله Weibull** (احتمال ۸٪): مدل‌سازی مکث‌های طولانی‌تر گاه‌به‌گاه (GC، scheduler jitter، ~۵-۲۰ms)
- **تطبیقی**: زمان سپری‌شده از SYN را اندازه می‌گیرد، فقط تأخیر باقی‌مانده را می‌خوابد

این توزیع تایمینگ را از اولین پکت داده یک مرورگر واقعی غیرقابل تشخیص می‌کند.

---

### جعل TTL (`bypass/fake_tcp.py`)

وقتی `TTL_SPOOF: true` باشد، پکت جعلی یک TTL تصادفی می‌گیرد:
- پایه: ۶۴ (Linux/macOS) یا ۱۲۸ (Windows) — به صورت تصادفی انتخاب می‌شود
- منهای ۱ تا ۸ هاپ — شبیه‌سازی یک هاست واقعی در فاصله شبکه

این از تشخیص پکت جعلی توسط DPI از طریق مقدار TTL جلوگیری می‌کند.

---

### محاسبه شماره Sequence

```python
fake_seq = (syn_seq + 1 - len(fake_payload)) & 0xFFFFFFFF
```

محدوده داده پکت جعلی را *قبل از* بایت مورد انتظار بعدی قرار می‌دهد — خارج از پنجره دریافت سرور. سرور آن را بی‌صدا دور می‌اندازد. DPI ابتدا آن را می‌بیند و SNI را ثبت می‌کند.

---

### فیلتر WinDivert

```
tcp and (
  (ip.SrcAddr == LOCAL_IP and ip.DstAddr == TARGET_IP)
  or
  (ip.SrcAddr == TARGET_IP and ip.DstAddr == LOCAL_IP)
)
```

فقط پکت‌های روی مسیر خاص `local ↔ target` رهگیری می‌شوند. تمام ترافیک دیگر بدون تغییر عبور می‌کند.

---

### مدل ترد

| مؤلفه | نقش |
|---|---|
| ترد اصلی | حلقه رویداد `asyncio` — پذیرش اتصال‌ها، مدیریت تسک‌های رله |
| ترد WinDivert | ترد daemon — رهگیری و تزریق پکت‌ها به صورت همگام |
| Thread pool (64 worker) | مدیریت تسک‌های fake-send با تایمینگ انسانی |
| `asyncio.Event` (`t2a_event`) | سیگنال از ترد WinDivert به حلقه async هنگام تکمیل bypass |

---

### اتصال مجدد خودکار WinDivert

اگر درایور WinDivert crash کند یا handle از دست برود، injector به صورت خودکار با exponential backoff (0.5s تا حداکثر 30s) دوباره متصل می‌شود. نیازی به راه‌اندازی مجدد دستی نیست.

---

### استخراج SNI (`utils/sni_extractor.py`)

- تکه‌های TCP را تجمیع می‌کند تا یک TLS ClientHello کامل قابل پارس باشد (تا ۱۶ کیلوبایت)
- ClientHello‌های تکه‌تکه شده در چندین پکت TCP را مدیریت می‌کند
- رمزگشایی UTF-8 با fallback ASCII برای نام‌های دامنه بین‌المللی (IDN)
- تمام extension‌ها را در هر ترتیبی پیمایش می‌کند

---

## احترام به سازنده

این پروژه بر پایه کار اصلی **[patterniha](https://github.com/patterniha/SNI-Spoofing)** ساخته شده است — توسعه‌دهنده‌ای که با تلاش و دانش خود ابزارهایی می‌سازد تا مردم ایران بتوانند به اینترنت آزاد دسترسی داشته باشند. تمام احترام و اعتبار برای ایده، معماری و پیاده‌سازی اصلی متعلق به ایشان است.

پروژه اصلی: [github.com/patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

- **تلگرام:** [@patterniha](https://t.me/patterniha)
- **کانال:** [t.me/projectXhttp](https://t.me/projectXhttp)

---

## حمایت از توسعه‌دهنده

اگر NexNull به شما کمک می‌کند به اینترنت آزاد دسترسی داشته باشید، لطفاً از patterniha حمایت کنید — پروژه‌ها و برنامه‌های زیادی برای دسترسی همه مردم ایران به اینترنت آزاد در دست توسعه هستند که نیاز به حمایت شما دارند.

- **USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`
- **USDT (TRC20):** `TU5gKvKqcXPn8itp1DouBCwcqGHMemBm8o`

---

## لایسنس

GPL-3.0 — فایل [LICENSE](LICENSE) را ببینید
