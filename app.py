from flask import Flask, request, render_template, redirect, session, url_for
from logger import log_api_call, log_security_event, log_user_activity
from sequence_tracker import track_sequence, reset_sequence
from detector import analyze_abuse
from prevention import (apply_prevention, clear_user_state, get_all_states, get_cooldown_remaining,
                        get_user_state, observe_behavior, rate_limit_decision, requires_step_up,
                        reset_user_state, verify_step_up)
import csv
import os
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlencode
from urllib.request import Request, urlopen

app = Flask(__name__)
app.secret_key = "api-sentinel-demo-secret"

cart = {}
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "chingu@325"
registered_users = {}
registered_emails = {}   # username -> email address
USER_STORE = "users.csv"
pending_registrations = {}
OTP_EXPIRY_MINUTES = 10


def admin_required():
    return session.get("admin_logged_in") is True


def client_fingerprint():
    """A small demo fingerprint; no raw device data is persisted to disk."""
    return "|".join([
        request.headers.get("User-Agent", "unknown")[:160],
        request.headers.get("Accept-Language", "unknown")[:80],
        request.remote_addr or "unknown",
    ])


def prevention_alert(user, api_name, result, prevention):
    log_security_event(user, api_name, result, prevention)
    if prevention.get("session_revoked"):
        session.clear()
    return render_template("abuse_alert.html", user=user, api_name=api_name,
                           analysis=result, prevention=prevention), prevention["http_status"]


def load_registered_users():
    if not os.path.exists(USER_STORE):
        return

    with open(USER_STORE) as file:
        reader = csv.reader(file)

        for row in reader:
            if len(row) >= 2:
                registered_users[row[0]] = row[1]
            if len(row) >= 3 and row[2].strip():
                registered_emails[row[0]] = row[2].strip()


def save_registered_user(user, password, email="", phone=""):
    with open(USER_STORE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([user, password, email, phone])


def load_env_file(filepath=".env"):
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k and k not in os.environ:
                    os.environ[k] = v

load_env_file()


def send_verification_otp(email, otp):
    """Send email when SMTP is configured; return True if sent, False if fallback to local delivery."""
    smtp_host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    if not smtp_host or not sender:
        print(f"\n[API Sentinel DEMO] Email verification code for {email}: {otp}\n", flush=True)
        return False

    message = EmailMessage()
    message["Subject"] = f"API Sentinel – Verification Code: {otp}"
    message["From"] = sender
    message["To"] = email
    message.set_content(f"Your API Sentinel verification code is: {otp}. It expires in {OTP_EXPIRY_MINUTES} minutes.")
    message.add_alternative(
        f"""\
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; margin: 0; padding: 0; }}
    .wrapper {{ max-width: 500px; margin: 30px auto; background: #1e293b; border-radius: 16px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    .header {{ background: linear-gradient(135deg, #00adb5, #6366f1); padding: 24px 30px; text-align: center; }}
    .header h1 {{ color: #ffffff; margin: 0; font-size: 22px; font-weight: 800; letter-spacing: 0.5px; }}
    .content {{ padding: 30px; text-align: center; color: #cbd5e1; }}
    .content h2 {{ color: #f8fafc; font-size: 18px; margin-top: 0; }}
    .otp-box {{ margin: 24px auto; padding: 18px 24px; background: #0f172a; border: 2px dashed #00adb5; border-radius: 12px; display: inline-block; }}
    .otp-code {{ font-size: 36px; font-weight: 900; letter-spacing: 8px; color: #38bdf8; margin: 0; font-family: monospace; }}
    .subtext {{ color: #94a3b8; font-size: 13px; margin-top: 16px; }}
    .footer {{ background: #0f172a; padding: 16px; text-align: center; color: #64748b; font-size: 12px; }}
  </style>
</head>
<body>
  <div class="wrapper">
    <div class="header">
      <h1>🛡️ API Sentinel</h1>
    </div>
    <div class="content">
      <h2>Verify Your Email Address</h2>
      <p>Enter the 6-digit confirmation code below to activate your API Sentinel account:</p>
      <div class="otp-box">
        <p class="otp-code">{otp}</p>
      </div>
      <p class="subtext">This code will expire in <strong>{OTP_EXPIRY_MINUTES} minutes</strong>.<br>If you did not request this code, please ignore this email.</p>
    </div>
    <div class="footer">API Sentinel Security System • Automated Message</div>
  </div>
</body>
</html>
""",
        subtype="html"
    )
    try:
        with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
            if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                smtp.starttls()
            if os.getenv("SMTP_USERNAME"):
                smtp_pass = os.getenv("SMTP_PASSWORD", "").replace(" ", "").strip()
                smtp.login(os.getenv("SMTP_USERNAME"), smtp_pass)
            smtp.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as e:
        print(f"\n[API Sentinel DEMO] SMTP error ({e}). Fallback verification code for {email}: {otp}\n", flush=True)
        return False


def send_login_email(user, email):
    """Send a login-notification email to the authenticated user."""
    smtp_host = os.getenv("SMTP_HOST")
    sender = os.getenv("SMTP_FROM")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_addr = request.remote_addr or "unknown"

    if not smtp_host or not sender:
        print(f"\n[API Sentinel DEMO] Login notification for {user} ({email}) at {now} from IP {ip_addr}\n", flush=True)
        return False

    message = EmailMessage()
    message["Subject"] = "API Sentinel – New Login Detected"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Hello {user},\n\n"
        f"A new login to your API Sentinel account was detected.\n\n"
        f"  Time  : {now}\n"
        f"  IP    : {ip_addr}\n\n"
        f"If this was you, no action is needed.\n"
        f"If you did not log in, please change your password immediately.\n\n"
        f"-- API Sentinel Security Team"
    )
    message.add_alternative(
        f"""\
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; margin: 0; padding: 0; }}
    .wrapper {{ max-width: 520px; margin: 40px auto; background: #1e293b; border-radius: 12px;
                overflow: hidden; box-shadow: 0 8px 32px rgba(0,0,0,.5); }}
    .header {{ background: linear-gradient(135deg, #6366f1, #8b5cf6); padding: 28px 32px; }}
    .header h1 {{ color: #fff; margin: 0; font-size: 20px; letter-spacing: .5px; }}
    .header p  {{ color: rgba(255,255,255,.75); margin: 4px 0 0; font-size: 13px; }}
    .body {{ padding: 28px 32px; color: #cbd5e1; font-size: 15px; line-height: 1.6; }}
    .body h2 {{ color: #f1f5f9; font-size: 17px; margin: 0 0 16px; }}
    .info-box {{ background: #0f172a; border: 1px solid #334155; border-radius: 8px;
                 padding: 16px 20px; margin: 20px 0; }}
    .info-box table {{ width: 100%; border-collapse: collapse; }}
    .info-box td {{ padding: 6px 0; font-size: 14px; }}
    .info-box td:first-child {{ color: #94a3b8; width: 80px; }}
    .info-box td:last-child  {{ color: #f1f5f9; font-weight: 600; }}
    .alert {{ color: #fbbf24; font-size: 13px; margin-top: 16px; }}
    .footer {{ background: #0f172a; padding: 16px 32px; text-align: center;
               color: #475569; font-size: 12px; }}
  </style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <h1>&#128274; API Sentinel</h1>
    <p>Security Notification</p>
  </div>
  <div class="body">
    <h2>New Login Detected</h2>
    <p>Hi <strong>{user}</strong>, a new login was recorded for your account.</p>
    <div class="info-box">
      <table>
        <tr><td>User</td><td>{user}</td></tr>
        <tr><td>Time</td><td>{now}</td></tr>
        <tr><td>IP</td><td>{ip_addr}</td></tr>
      </table>
    </div>
    <p>If this was you, no action is needed.</p>
    <p class="alert">&#9888;&#65039; If you did NOT log in, change your password immediately.</p>
  </div>
  <div class="footer">API Sentinel &bull; Automated Security Alert &bull; Do not reply</div>
</div>
</body>
</html>""",
        subtype="html"
    )
    try:
        with smtplib.SMTP(smtp_host, int(os.getenv("SMTP_PORT", "587")), timeout=10) as smtp:
            if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                smtp.starttls()
            if os.getenv("SMTP_USERNAME"):
                smtp_pass = os.getenv("SMTP_PASSWORD", "").replace(" ", "").strip()
                smtp.login(os.getenv("SMTP_USERNAME"), smtp_pass)
            smtp.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        print(f"\n[API Sentinel DEMO] SMTP error ({exc}). Login notification for {user} not sent.\n", flush=True)
        return False


def send_phone_otp(phone, otp):
    """Use Twilio only when its credentials are configured; otherwise local-demo delivery is used."""
    account_sid = os.getenv("TWILIO_ACCOUNT_SID")
    auth_token = os.getenv("TWILIO_AUTH_TOKEN")
    sender = os.getenv("TWILIO_FROM_PHONE")
    if not account_sid or not auth_token or not sender:
        return False
    payload = urlencode({
        "To": phone,
        "From": sender,
        "Body": f"Your API Sentinel phone verification code is: {otp}. It expires in {OTP_EXPIRY_MINUTES} minutes.",
    }).encode()
    request = Request(f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json", data=payload)
    import base64
    token = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    try:
        with urlopen(request, timeout=10):
            return True
    except OSError:
        return False


load_registered_users()

# Product database
products_list = {
    # ── Smartphones ──
    "iPhone 17 Pro Max": {
        "price": 149900,
        "img": "https://images.unsplash.com/photo-1695048133142-1a20484d2569?auto=format&fit=crop&w=600&q=80",
        "category": "Smartphone",
        "badge": "New"
    },
    "Samsung Galaxy S25 Ultra": {
        "price": 129900,
        "img": "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?auto=format&fit=crop&w=600&q=80",
        "category": "Smartphone",
        "badge": "Hot"
    },
    "OnePlus 13": {
        "price": 69999,
        "img": "https://images.unsplash.com/photo-1598327105666-5b89351aff97?auto=format&fit=crop&w=600&q=80",
        "category": "Smartphone",
        "badge": None
    },
    # ── Laptops ──
    "MacBook Pro M4": {
        "price": 199900,
        "img": "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?auto=format&fit=crop&w=600&q=80",
        "category": "Laptop",
        "badge": "Best Seller"
    },
    "Dell XPS 15": {
        "price": 159900,
        "img": "https://images.unsplash.com/photo-1593642632823-8f785ba67e45?auto=format&fit=crop&w=600&q=80",
        "category": "Laptop",
        "badge": None
    },
    "ASUS ROG Zephyrus G16": {
        "price": 179900,
        "img": "https://images.unsplash.com/photo-1603302576837-37561b2e2302?auto=format&fit=crop&w=600&q=80",
        "category": "Laptop",
        "badge": "Gaming"
    },
    # ── Tablets ──
    "iPad Pro M4": {
        "price": 109900,
        "img": "https://images.unsplash.com/photo-1544244015-0df4b3ffc6b0?auto=format&fit=crop&w=600&q=80",
        "category": "Tablet",
        "badge": "New"
    },
    "Samsung Galaxy Tab S10": {
        "price": 79900,
        "img": "https://images.unsplash.com/photo-1561154464-82e9adf32764?auto=format&fit=crop&w=600&q=80",
        "category": "Tablet",
        "badge": None
    },
    # ── Audio ──
    "AirPods Pro 3": {
        "price": 29900,
        "img": "https://images.unsplash.com/photo-1600294037681-c80b4cb5b434?auto=format&fit=crop&w=600&q=80",
        "category": "Audio",
        "badge": "New"
    },
    "Sony WH-1000XM6": {
        "price": 34990,
        "img": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?auto=format&fit=crop&w=600&q=80",
        "category": "Audio",
        "badge": "Top Rated"
    },
    "JBL Charge 6": {
        "price": 14999,
        "img": "https://images.unsplash.com/photo-1608043152269-423dbba4e7e1?auto=format&fit=crop&w=600&q=80",
        "category": "Audio",
        "badge": None
    },
    "Bose QuietComfort 45": {
        "price": 26900,
        "img": "https://images.unsplash.com/photo-1546435770-a3e426bf472b?auto=format&fit=crop&w=600&q=80",
        "category": "Audio",
        "badge": None
    },
    # ── Wearables ──
    "Apple Watch Ultra 3": {
        "price": 89900,
        "img": "https://images.unsplash.com/photo-1546868871-7041f2a55e12?auto=format&fit=crop&w=600&q=80",
        "category": "Smartwatch",
        "badge": "Premium"
    },
    "Samsung Galaxy Watch 7": {
        "price": 34999,
        "img": "https://images.unsplash.com/photo-1508685096489-7aacd43bd3b1?auto=format&fit=crop&w=600&q=80",
        "category": "Smartwatch",
        "badge": None
    },
    "Fitbit Sense 3": {
        "price": 19999,
        "img": "https://images.unsplash.com/photo-1575311373937-040b8e1fd5b6?auto=format&fit=crop&w=600&q=80",
        "category": "Smartwatch",
        "badge": None
    },
    # ── Accessories ──
    "Logitech MX Master 3S": {
        "price": 11995,
        "img": "https://images.unsplash.com/photo-1615663245857-ac93bb7c39e7?auto=format&fit=crop&w=600&q=80",
        "category": "Accessory",
        "badge": None
    },
    "Keychron Q5 Pro": {
        "price": 19990,
        "img": "https://images.unsplash.com/photo-1587829741301-dc798b83add3?auto=format&fit=crop&w=600&q=80",
        "category": "Accessory",
        "badge": "Trending"
    },
    "Anker USB-C Hub 12-in-1": {
        "price": 5999,
        "img": "https://images.unsplash.com/photo-1625842268584-8f3296236761?auto=format&fit=crop&w=600&q=80",
        "category": "Accessory",
        "badge": None
    },
    "Logitech C930e Webcam": {
        "price": 9499,
        "img": "https://images.unsplash.com/photo-1588508065123-287b28e013da?auto=format&fit=crop&w=600&q=80",
        "category": "Accessory",
        "badge": None
    },
    "Samsung 65\" QLED 4K TV": {
        "price": 129990,
        "img": "https://images.unsplash.com/photo-1593359677879-a4bb92f829d1?auto=format&fit=crop&w=600&q=80",
        "category": "TV",
        "badge": "Deal"
    },
}


@app.route("/")
def home():
    return render_template("login.html", error=None, success=None)


@app.route("/admin")
def admin_login():

    return redirect(url_for("home"))


@app.route("/admin/logout")
def admin_logout():

    log_user_activity(ADMIN_USERNAME, "logout", "Admin logged out", "admin")
    session.pop("admin_logged_in", None)

    return redirect(url_for("home"))


# ---------------- SECURITY CHECK ----------------
def process_request(user, api_name):

    if not user:
        user = "anonymous"

    if user == ADMIN_USERNAME and api_name != "login":
        return redirect(url_for("dashboard"))

    # The user query parameter is only used to keep the demo links readable.
    # It is never accepted as proof of authentication: protected pages must
    # belong to the currently authenticated browser session.
    if api_name not in {"login", "admin-test", "debug", "internal"} and session.get("authenticated_user") != user:
        return redirect(url_for("home"))

    behavior = observe_behavior(user, client_fingerprint())
    if api_name != "login" and behavior["rate_limited"]:
        result = {
            "status": "Abuse Detected", "title": "Adaptive Rate Limit Exceeded", "risk": "High", "risk_score": 83,
            "summary": "Request velocity exceeded the session's behavior-based API limit.",
            "reason": "The rate limit tightens from 100 to 20 requests per minute after suspicious behavior.",
            "violated_rule": "requests must remain within the adaptive per-minute limit", "missing_step": None,
            "expected_flow": ["login", "products", "add-to-cart", "checkout", "pay"], "observed_flow": track_sequence(user, api_name),
            "recommendation": "Temporarily restrict the session and continue monitoring for automation or replay behavior.",
        }
        return prevention_alert(user, api_name, result, rate_limit_decision(user, behavior))

    state = get_user_state(user)
    cooldown_remaining = get_cooldown_remaining(user)

    if api_name != "login" and cooldown_remaining > 0:
        sequence = track_sequence(user, api_name)
        result = {
            "status": "Abuse Detected",
            "title": "Adaptive Cooldown Active",
            "risk": "Medium",
            "risk_score": 68,
            "summary": "The user attempted a protected request while a progressive cooldown restriction was still active.",
            "reason": "Progressive risk-based prevention slows repeated abnormal behavior before escalating to a workflow lock or quarantine.",
            "violated_rule": "cooldown period must expire before another protected workflow request",
            "missing_step": None,
            "expected_flow": ["login", "products", "add-to-cart", "checkout", "pay"],
            "observed_flow": sequence,
            "recommendation": "Keep the temporary restriction active and allow the user to retry after the cooldown expires.",
        }
        prevention = {
            "action": "Adaptive Cooldown",
            "blocked": True,
            "http_status": 429,
            "trust_score": state["trust_score"],
            "violations": state["violations"],
            "workflow_locked": state["workflow_locked"],
            "quarantined": state["quarantined"],
            "cooldown_seconds": cooldown_remaining,
            "message": f"Temporary restriction active. Retry after {cooldown_remaining} seconds.",
        }
        return prevention_alert(user, api_name, result, prevention)

    if api_name != "login" and (state["workflow_locked"] or state["quarantined"]):
        sequence = track_sequence(user, api_name)
        result = {
            "status": "Abuse Detected",
            "title": "Workflow Locked",
            "risk": "Critical" if state["quarantined"] else "High",
            "risk_score": 92 if state["quarantined"] else 78,
            "summary": "The user attempted another protected request after the prevention engine locked the workflow.",
            "reason": "After repeated or high-risk sequence violations, the framework prevents continuation from an unsafe workflow state.",
            "violated_rule": "locked workflows must restart from login",
            "missing_step": "login",
            "expected_flow": ["login", "products", "add-to-cart", "checkout", "pay"],
            "observed_flow": sequence,
            "recommendation": "Keep the request blocked and require a fresh login before allowing workflow APIs again.",
        }
        prevention = apply_prevention(user, result)
        return prevention_alert(user, api_name, result, prevention)

    log_api_call(user, api_name)

    sequence = track_sequence(user, api_name)

    result = analyze_abuse(sequence)
    prevention = apply_prevention(user, result)

    if result["status"] != "Normal":
        return prevention_alert(user, api_name, result, prevention)

    if requires_step_up(user, api_name):
        return render_template("step_up.html", user=user, api_name=api_name), 401

    return None


# ---------------- LOGIN ----------------
@app.route("/login", methods=["POST"])
def login():

    user = request.form.get("user", "").strip()
    password = request.form.get("password", "")

    if user == ADMIN_USERNAME:
        if password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            log_user_activity(user, "login", "Admin dashboard access", "admin")
            return redirect(url_for("dashboard"))

        log_user_activity(user or "admin", "login", "Invalid admin password", "admin")
        return render_template(
            "login.html",
            error="Invalid admin password.",
            success=None
        )

    if user not in registered_users:
        log_user_activity(user or "unknown", "login", "User not registered", "user")
        return render_template(
            "login.html",
            error="User not registered. Please register first.",
            success=None
        )

    if registered_users[user] != password:
        log_user_activity(user, "login", "Invalid user password", "user")
        return render_template(
            "login.html",
            error="Invalid username or password.",
            success=None
        )

    reset_sequence(user)
    reset_user_state(user)
    session.clear()
    session["authenticated_user"] = user

    response = process_request(user, "login")
    if response:
        return response

    log_user_activity(user, "login", "User workflow access", "user")
    cart[user] = []

    # Send login-notification email if the user has a registered email address
    user_email = registered_emails.get(user)
    if user_email:
        send_login_email(user, user_email)

    return redirect("/products?user=" + user)


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html", error=None, user="", email="")

    user = request.form.get("user", "").strip()
    password = request.form.get("password", "")
    email = request.form.get("email", "").strip().lower()

    if not user or not password or not email:
        return render_template(
            "register.html",
            error="Enter a username, email address, and password to register.",
            user=user,
            email=email
        )

    if "@" not in email or email.startswith("@") or email.endswith("@"):
        return render_template("register.html", error="Enter a valid email address.", user=user, email=email)

    if user == ADMIN_USERNAME:
        return render_template(
            "register.html",
            error="This username is reserved for the administrator.",
            user=user,
            email=email
        )

    if user in registered_users:
        return render_template(
            "register.html",
            error="User already registered. Please login.",
            user=user,
            email=email
        )

    email_otp = f"{secrets.randbelow(1_000_000):06d}"
    email_delivered = send_verification_otp(email, email_otp)
    demo_otp = None if email_delivered else email_otp

    pending_registrations[user] = {
        "password": password,
        "email": email,
        "email_otp": email_otp,
        "demo_otp": demo_otp,
        "email_delivered": email_delivered,
        "expires_at": datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES),
    }
    
    activity_msg = "Email verification sent" if email_delivered else "Email verification pending (local demo delivery)"
    log_user_activity(user, "register", activity_msg, "user")

    return render_template("verify_email.html", user=user, email=email,
                           demo_otp=demo_otp, email_delivered=email_delivered,
                           error=None)


@app.route("/verify-email", methods=["POST"])
def verify_email():
    user = request.form.get("user", "").strip()
    email_otp = request.form.get("email_otp", "").strip()
    pending = pending_registrations.get(user)

    if not pending:
        return render_template("register.html", error="Verification session expired or not found. Please register again.")
    if datetime.now() > pending["expires_at"]:
        pending_registrations.pop(user, None)
        return render_template("register.html", error="Verification code expired. Please register again.")
    if not secrets.compare_digest(email_otp, pending["email_otp"]):
        return render_template("verify_email.html", user=user, email=pending["email"],
                               demo_otp=pending.get("demo_otp"),
                               email_delivered=pending.get("email_delivered", False),
                               error="Email verification code is invalid. Please try again.")

    registered_users[user] = pending["password"]
    if pending["email"]:
        registered_emails[user] = pending["email"]
    save_registered_user(user, pending["password"], pending["email"])
    pending_registrations.pop(user, None)
    log_user_activity(user, "email-verification", "Email verified; account activated", "user")

    return render_template(
        "login.html",
        error=None,
        success=f"Account created successfully for '{user}'. You can now log in."
    )


@app.route("/verify-step-up", methods=["POST"])
def verify_step_up_authentication():
    user = request.form.get("user", "").strip()
    api_name = request.form.get("api_name", "checkout")
    otp = request.form.get("otp", "")

    # Demo-only OTP; production code should delegate this verification to an MFA provider.
    if otp != "123456":
        return render_template("step_up.html", user=user, api_name=api_name,
                               error="Invalid verification code. Use 123456 in this demo."), 401

    verify_step_up(user)
    log_user_activity(user, "step-up-authentication", f"Verified before {api_name}", "user")
    return redirect(url_for("checkout" if api_name == "checkout" else "pay", user=user))


# ---------------- PRODUCTS ----------------
@app.route("/products")
def products():

    user = request.args.get("user")

    response = process_request(user, "products")
    if response:
        return response

    products = []

    for name in products_list:
        pdata = products_list[name]
        product_img = pdata["img"]
        products.append({
            "name": name,
            "price": pdata["price"],
            "img": product_img,
            "category": pdata.get("category", ""),
            "badge": pdata.get("badge"),
            "is_external_img": product_img.startswith("http://") or product_img.startswith("https://")
        })

    return render_template("products.html", user=user, products=products)


# ---------------- ADD TO CART ----------------
@app.route("/add-to-cart")
def add_to_cart():

    user = request.args.get("user")
    item = request.args.get("item")
    qty = max(1, min(10, int(request.args.get("qty", 1) or 1)))

    response = process_request(user, "add-to-cart")
    if response:
        return response

    if item not in products_list:
        result = {
            "status": "Abuse Detected",
            "title": "Invalid Product Request",
            "risk": "Medium",
            "risk_score": 65,
            "summary": "The add-to-cart API received a product name that does not exist in the catalog.",
            "reason": "A cart request with an unknown product can indicate parameter tampering or endpoint probing.",
            "violated_rule": "add-to-cart item must exist in the product catalog",
            "missing_step": None,
            "expected_flow": ["login", "products", "add-to-cart", "checkout", "pay"],
            "observed_flow": ["add-to-cart"],
            "recommendation": "Block the request and ask the user to choose a valid product from the products page.",
        }
        prevention = apply_prevention(user, result)
        log_security_event(user, "add-to-cart", result, prevention)

        return render_template(
            "abuse_alert.html",
            user=user,
            api_name="add-to-cart",
            analysis=result,
            prevention=prevention
        ), prevention["http_status"]

    product = {
        "name": item,
        "price": products_list[item]["price"]
    }

    if user not in cart:
        cart[user] = []

    for _ in range(qty):
        cart[user].append(product)

    items = cart.get(user, [])
    total = sum(i["price"] for i in items)

    return render_template(
        "cart.html",
        user=user,
        item=product,
        qty=qty,
        items=items,
        total=total,
        item_count=len(items)
    )


@app.route("/cart")
def view_cart():

    user = request.args.get("user")

    response = process_request(user, "cart")
    if response:
        return response

    items = cart.get(user, [])
    total = sum(item["price"] for item in items)

    return render_template(
        "cart.html",
        user=user,
        item=None,
        items=items,
        total=total,
        item_count=len(items)
    )


# ---------------- CHECKOUT ----------------
@app.route("/checkout")
def checkout():

    user = request.args.get("user")

    response = process_request(user, "checkout")
    if response:
        return response

    items = cart.get(user, [])

    total = sum(item["price"] for item in items)

    return render_template("checkout.html", user=user, items=items, total=total)


# ---------------- PAYMENT ----------------
@app.route("/pay")
def pay():

    user = request.args.get("user")

    response = process_request(user, "pay")
    if response:
        return response

    cart[user] = []
    reset_sequence(user)
    reset_user_state(user)
    log_user_activity(user, "payment", "Workflow completed", "user")

    return render_template("payment_success.html", user=user)


@app.route("/logout")
def logout():

    user = request.args.get("user") or session.get("authenticated_user") or "anonymous"

    reset_sequence(user)
    reset_user_state(user)
    cart.pop(user, None)
    session.clear()
    log_user_activity(user, "logout", "User logged out", "user")

    return redirect("/")


@app.route("/api/admin_test")
@app.route("/api/debug")
@app.route("/api/internal")
def honeypot_api():

    user = request.args.get("user", "anonymous")
    api_name = request.path.rsplit("/", 1)[-1].replace("_", "-")

    response = process_request(user, api_name)
    if response:
        return response

    return "Honeypot endpoint blocked", 403


@app.route("/dashboard")
def dashboard():

    if not admin_required():
        return redirect(url_for("home"))

    logs = []
    events = []
    api_counts = {}
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    action_counts = {}
    user_activities = []
    user_status = {}
    users = set()

    if os.path.exists("api_logs.csv"):
        with open("api_logs.csv") as f:
            reader = csv.reader(f)

            for row in reader:
                if len(row) < 3:
                    continue

                logs.append(row)
                users.add(row[0])

                api = row[1]

                if api not in api_counts:
                    api_counts[api] = 0

                api_counts[api] += 1

    if os.path.exists("security_events.csv"):
        with open("security_events.csv") as f:
            reader = csv.reader(f)

            for row in reader:
                if len(row) < 9:
                    continue

                events.append(row)
                users.add(row[0])

                risk = row[3]
                action = row[5]

                risk_counts[risk] = risk_counts.get(risk, 0) + 1
                action_counts[action] = action_counts.get(action, 0) + 1

    if os.path.exists("user_activity.csv"):
        with open("user_activity.csv") as f:
            reader = csv.reader(f)

            for row in reader:
                if len(row) < 5:
                    continue

                user_activities.append(row)
                user = row[0]
                role = row[1]
                action = row[2]
                status = row[3]
                timestamp = row[4]
                users.add(user)

                user_status[user] = {
                    "role": role,
                    "last_action": action,
                    "status": status,
                    "last_seen": timestamp
                }

    for user in registered_users:
        if user not in user_status:
            user_status[user] = {
                "role": "user",
                "last_action": "registered",
                "status": "Registered",
                "last_seen": "Not logged in yet"
            }
            users.add(user)

    total_requests = len(logs)
    suspicious_requests = len(events)
    normal_requests = max(0, total_requests - suspicious_requests)
    blocked_requests = sum(1 for event in events if event[5] != "Warning")
    detection_rate = round((suspicious_requests / total_requests) * 100, 2) if total_requests else 0
    failed_logins = sum(1 for activity in user_activities if "Invalid" in activity[3] or "not registered" in activity[3])
    user_states = get_all_states()
    trust_scores = [state["trust_score"] for state in user_states.values()]
    average_trust = round(sum(trust_scores) / len(trust_scores), 1) if trust_scores else 100
    locked_sessions = sum(1 for state in user_states.values() if state["workflow_locked"])
    quarantined_sessions = sum(1 for state in user_states.values() if state["quarantined"])
    cooldown_events = action_counts.get("Adaptive Cooldown", 0)
    warning_events = action_counts.get("Warning", 0)
    workflow_lock_events = action_counts.get("Workflow Lock", 0)
    quarantine_events = action_counts.get("Block + Quarantine", 0)
    rate_limit_events = action_counts.get("Adaptive Rate Limit", 0)
    step_up_verifications = sum(1 for activity in user_activities if activity[2] == "step-up-authentication")
    prevention_mechanisms = [
        {
            "name": "Sequence Trust Scoring",
            "metric": average_trust,
            "label": "Average Trust",
            "description": "Every abnormal sequence reduces the user's behavioral trust score according to risk severity.",
            "status": "low" if average_trust >= 80 else "medium" if average_trust >= 50 else "high",
        },
        {
            "name": "Dynamic Workflow Locking",
            "metric": locked_sessions,
            "label": "Locked Sessions",
            "description": "High-risk sequence violations stop protected workflow APIs until the user restarts from login.",
            "status": "low" if locked_sessions == 0 else "high",
        },
        {
            "name": "Progressive Risk Response",
            "metric": warning_events + cooldown_events + workflow_lock_events + quarantine_events,
            "label": "Adaptive Actions",
            "description": "The response escalates from warning to cooldown, workflow lock, and quarantine as risk increases.",
            "status": "low" if suspicious_requests == 0 else "medium",
        },
        {
            "name": "Adaptive Rate Limiting",
            "metric": rate_limit_events,
            "label": "Rate Restrictions",
            "description": "Request limits contract from 100 to 20 per minute for risky sessions, then to zero in quarantine.",
            "status": "low" if rate_limit_events == 0 else "high",
        },
        {
            "name": "Step-Up Authentication",
            "metric": step_up_verifications,
            "label": "Verifications",
            "description": "Sensitive checkout and payment operations require a one-time verification after suspicious behavior.",
            "status": "low" if step_up_verifications == 0 else "medium",
        },
    ]

    return render_template(
        "dashboard.html",
        logs=logs[-25:],
        events=events[-25:],
        api_counts=api_counts,
        risk_counts=risk_counts,
        action_counts=action_counts,
        total_requests=total_requests,
        normal_requests=normal_requests,
        suspicious_requests=suspicious_requests,
        blocked_requests=blocked_requests,
        active_users=len(users),
        active_alerts=suspicious_requests,
        monitored_apis=len(api_counts),
        detection_rate=detection_rate,
        user_states=user_states,
        prevention_mechanisms=prevention_mechanisms,
        locked_sessions=locked_sessions,
        quarantined_sessions=quarantined_sessions,
        cooldown_events=cooldown_events,
        rate_limit_events=rate_limit_events,
        step_up_verifications=step_up_verifications,
        user_activities=user_activities[-30:],
        user_status=user_status,
        registered_user_count=len(registered_users),
        failed_logins=failed_logins
    )


@app.route("/simulate-attacks")
def simulate_attacks():

    if not admin_required():
        return redirect(url_for("home"))

    scenarios = [
        {
            "name": "Direct Checkout Bypass",
            "flow": ["login", "checkout"],
            "description": "User skips product selection and cart creation.",
        },
        {
            "name": "Unauthenticated Products Access",
            "flow": ["products"],
            "description": "Protected product API is requested without login.",
        },
        {
            "name": "Payment Bypass",
            "flow": ["login", "products", "pay"],
            "description": "Payment is invoked before checkout validation.",
        },
        {
            "name": "Repeated Checkout Replay",
            "flow": ["login", "products", "add-to-cart", "checkout", "checkout"],
            "description": "Checkout is replayed more than once in one tracked workflow.",
        },
        {
            "name": "Hidden Admin Probe",
            "flow": ["login", "admin-test"],
            "description": "A hidden honeypot endpoint is requested.",
        },
        {
            "name": "Normal User Purchase",
            "flow": ["login", "products", "add-to-cart", "checkout", "pay"],
            "description": "Expected sequence used as the baseline control case.",
        },
    ]

    results = []

    for index, scenario in enumerate(scenarios):
        analysis = analyze_abuse(scenario["flow"])
        simulation_user = f"simulation-preview-{index}"
        prevention = apply_prevention(simulation_user, analysis)
        clear_user_state(simulation_user)
        results.append({
            "name": scenario["name"],
            "flow": scenario["flow"],
            "description": scenario["description"],
            "analysis": analysis,
            "prevention": prevention,
        })

    return render_template("simulations.html", results=results)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
