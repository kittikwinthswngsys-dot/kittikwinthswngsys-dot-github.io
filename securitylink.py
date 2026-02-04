from flask import Flask, render_template_string, request, abort
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import os

# =========================
# CONFIG
# =========================

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY not set")

csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["500 per day"],
    storage_uri="memory://"
)

# =========================
# SECURITY HEADERS TO CHECK
# =========================

SECURITY_HEADERS = {
    "Content-Security-Policy": "นโยบายแหล่งที่มาของเนื้อหา",
    "X-Frame-Options": "ป้องกันการฝังเว็บ (Clickjacking)",
    "X-Content-Type-Options": "ป้องกันการเดาประเภทไฟล์",
    "Strict-Transport-Security": "บังคับใช้ HTTPS",
    "Referrer-Policy": "นโยบายการส่งข้อมูลอ้างอิง",
    "Permissions-Policy": "ควบคุมสิทธิ์การใช้งานเบราว์เซอร์",
    "Cache-Control": "การควบคุมแคชข้อมูล",
    "Cross-Origin-Opener-Policy": "การแยกหน้าต่างข้ามโดเมน",
    "Cross-Origin-Resource-Policy": "การเข้าถึงทรัพยากรข้ามโดเมน"
}


# =========================
# UTIL FUNCTIONS
# =========================

def validate_url(url: str) -> bool:
    if not url or len(url) > 200:
        return False
    parsed = urlparse(url)
    return parsed.scheme in ["http", "https"] and bool(parsed.netloc)

def get_tls_version(host):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            return s.version()
    except:
        return "Unknown"

def check_headers(headers):
    return {
        SECURITY_HEADERS[h]: h in headers
        for h in SECURITY_HEADERS
    }


def check_cookie_flags(headers):
    cookies = headers.get("Set-Cookie", "").lower()
    return {
        "HttpOnly (ป้องกัน XSS)": "httponly" in cookies,
        "Secure (ใช้ HTTPS เท่านั้น)": "secure" in cookies,
        "SameSite (ป้องกัน CSRF)": "samesite" in cookies
    }

def check_cors(headers):
    return {
        "อนุญาต Origin": headers.get("Access-Control-Allow-Origin", "ไม่กำหนด"),
        "ส่ง Cookie ข้ามโดเมน": headers.get("Access-Control-Allow-Credentials", "ไม่กำหนด")
    }

def analyze_html(html):
    soup = BeautifulSoup(html, "html.parser")
    return {
        "ฟอร์มทั้งหมด": len(soup.find_all("form")),
        "ช่องรหัสผ่าน": len(soup.find_all("input", {"type": "password"})),
        "Iframe": len(soup.find_all("iframe")),
        "สคริปต์ภายนอก": len([s for s in soup.find_all("script") if s.get("src")]),
        "สคริปต์ฝังในหน้าเว็บ": len([s for s in soup.find_all("script") if not s.get("src")])
    }

def scan_website(url):
    parsed = urlparse(url)
    host = parsed.hostname

    r = requests.get(url, timeout=10)

    return {
        "https": parsed.scheme == "https",
        "tls": get_tls_version(host),
        "headers": check_headers(r.headers),
        "cookies": check_cookie_flags(r.headers),
        "cors": check_cors(r.headers),
        "server": r.headers.get("Server", "Hidden"),
        "powered": r.headers.get("X-Powered-By", "Hidden"),
        "html": analyze_html(r.text),
        "status": r.status_code
    }

# =========================
# RESPONSE SECURITY HEADERS
# =========================

@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    return response

# =========================
# FRONTEND
# =========================

HTML = """
<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Scanner link</title> 
<link rel="icon" type="png" href="b9b528b8-6fcb-4cb8-a102-7b05738d2b9e.jpg">

<style>
:root {
    --indigo: #1a1aff;
    --indigo-dark: #12007a;
    --light: #ffffff;
    --bg: #f6f8ff;
    --success: #1ec98b;
    --danger: #ff4d4d;
}

/* ===== Global ===== */
body {
    margin: 0;
    font-family: 'Segoe UI', sans-serif;
    background: var(--bg);
    color: #222;
    animation: fadeIn 1s ease;
}

@keyframes fadeIn {
    from { opacity: 0 }
    to { opacity: 1 }
}

.container {
    max-width: 1100px;
    margin: auto;
    padding: 40px 20px;
}

/* ===== Header ===== */
.color-block {
    height: 220px;
    background: linear-gradient(135deg, #1a1aff, #3f8cff);
    border-radius: 25px;

    display: flex;
    flex-direction: column;   /* ⭐ สำคัญ */
    justify-content: center;
    align-items: center;

    box-shadow: 0 20px 40px rgba(26,26,255,0.3);
    margin-bottom: 50px;
    animation: slideDown 1s ease;
}


@keyframes slideDown {
    from { transform: translateY(-40px); opacity: 0 }
    to { transform: translateY(0); opacity: 1 }
}

.overlay-box {
    font-size: 34px;
    font-weight: 800;
    color: white;
    letter-spacing: 1px;
    text-align: center;
}

.overlay-box1 {
    font-size: 14px;
    font-weight: 400;
    color: white;
    letter-spacing: 1px;
    margin-top: 10px;   /* เว้นระยะจากหัวข้อ */
    text-align: center;
}


/* ===== Form ===== */
form {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 20px;
    margin-bottom: 60px;
}

textarea {
    width: 100%;
    max-width: 620px;
    height: 55px;
    padding: 15px;
    font-size: 16px;
    border-radius: 15px;
    border: 2px solid #ddd;
    transition: all 0.3s ease;
}

textarea:focus {
    outline: none;
    border-color: var(--indigo);
    box-shadow: 0 0 15px rgba(26,26,255,0.3);
}

button {
    padding: 14px 45px;
    font-size: 18px;
    border-radius: 40px;
    border: none;
    cursor: pointer;
    font-weight: bold;
    color: white;
    background: linear-gradient(135deg, #1a1aff, #4da3ff);
    box-shadow: 0 10px 25px rgba(26,26,255,0.4);
    transition: all 0.3s ease;
}

button:hover {
    transform: translateY(-3px) scale(1.03);
    box-shadow: 0 15px 35px rgba(26,26,255,0.6);
}

/* ===== Result ===== */
.result-container {
    background: white;
    border-radius: 25px;
    padding: 35px;
    animation: fadeUp 0.8s ease;
}

@keyframes fadeUp {
    from { opacity: 0; transform: translateY(30px) }
    to { opacity: 1; transform: translateY(0) }
}

h2, h3 {
    color: var(--indigo);
}

.info-bar {
    margin-top: 25px;
    background: #eef1ff;
    padding: 18px;
    border-radius: 15px;
    display: flex;
    justify-content: space-around;
    flex-wrap: wrap;
    font-size: 15px;
}

/* ===== Cards ===== */
.grid-results {
    margin-top: 30px;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px,1fr));
    gap: 25px;
}

.card {
    background: #fafbff;
    padding: 25px;
    border-radius: 20px;
    border: 1px solid #e6e9ff;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.card:hover {
    transform: translateY(-8px);
    box-shadow: 0 15px 30px rgba(0,0,0,0.1);
}

/* ===== Lists ===== */
ul {
    list-style: none;
    padding: 0;
}

li {
    display: flex;
    justify-content: space-between;
    padding: 10px 0;
    border-bottom: 1px dashed #ddd;
}

/* ===== Status ===== */
.status-badge {
    padding: 4px 14px;
    border-radius: 20px;
    font-size: 0.8em;
    font-weight: bold;
}

.ok {
    white-space: nowrap;
    background: rgba(30,201,139,0.15);
    color: var(--success);
    padding: 4px 8px;
    border-radius: 6px;
}

@keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(30,201,139,0.5) }
    70% { box-shadow: 0 0 0 10px rgba(30,201,139,0) }
    100% { box-shadow: 0 0 0 0 rgba(30,201,139,0) }
}

.bad {
    white-space: nowrap;
    background: rgba(255,77,77,0.15);
    color: var(--danger);
    padding: 4px 8px;
    border-radius: 6px;
}

/* ===== Footer ===== */
.footer {
    margin-top: 35px;
    padding-top: 15px;
    border-top: 1px solid #eee;
    font-size: 0.9em;
    color: #666;
}
</style>
</head>

<body>

<div class="container">

    <div class="color-block">
        <div class="overlay-box">Welcome To Website Scanner link</div>
        <div class="overlay-box1">เว็ปไซต์นี้เป็นเว็ปไซต์สำหรับการตรวจสอบข้อมูลความปลอดภัยของเว็บไซต์</div>
    </div>

    <form method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <textarea name="url" placeholder="ใส่ URL ที่ต้องการสแกน เช่น https://example.com"></textarea>
        <button type="submit">เริ่มการสแกน</button>
    </form>

    {% if result %}
    <div class="result-container">

        <h2>ผลการสแกน:
            <small style="color:#666">{{ result.url if result.url else '' }}</small>
        </h2>

        <div class="info-bar">
            <span>การเปิดใช้HTTPS: <b class="{{ 'ok' if result.https else 'bad' }}">{{ 'มีการเปิดใช้งาน' if result.https else 'ไม่มีการเปิดใช้งาน' }}</b></span>
            <span>โปรโตคอลเข้ารหัสข้อมูล: <b>{{ result.tls }}</b></span>
            <span>สถานะตอบกลับเซิร์ฟเวอร์: <b>{{ result.status }}</b></span>
        </div>

        <div class="grid-results">

            <div class="card">
                <h3>ส่วนควบคุมความปลอดภัยของเว็บ</h3>
                <ul>
                {% for k,v in result.headers.items() %}
                <li>
                    <span>{{ k }}</span>
                    <span class="status-badge {{ 'ok' if v else 'bad' }}">{{ 'มีการจัดการ' if v else 'ไม่มีการจัดการ' }}</span>
                </li>
                {% endfor %}
                </ul>
            </div>

            <div class="card">
                <h3>ความปลอดภัยของคุกกี้</h3>
                <ul>
                {% for k,v in result.cookies.items() %}
                <li>
                    <span>{{ k }}</span>
                    <span class="status-badge {{ 'ok' if v else 'bad' }}">{{ 'มีการป้องกัน' if v else 'ไม่มีการป้องกัน' }}</span>
                </li>
                {% endfor %}
                </ul>
            </div>

            <div class="card">
                <h3>CORS และโครงสร้างเว็บไซต์</h3>
                <ul>
                {% for k,v in result.cors.items() %}
                <li>{{ k }}: <b>{{ v }}</b></li>
                {% endfor %}
                {% for k,v in result.html.items() %}
                <li>{{ k }}: <b>{{ v }}</b></li>
                {% endfor %}
                </ul>
            </div>

        </div>

        <div class="footer">
            Server: {{ result.server }} |
            เทคโนโลยีที่ใช้: {{ result.powered }}
        </div>

    </div>
    {% endif %}

</div>

</body>
</html>
"""

# =========================
# ROUTE
# =========================

@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def home():
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not validate_url(url):
            abort(400)
        result = scan_website(url)

    return render_template_string(HTML, result=result)

# =========================
# RUN
# =========================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=port, debug=False)









