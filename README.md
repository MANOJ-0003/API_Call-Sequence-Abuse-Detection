# 🛡️ API Call Sequence Abuse Detection & Adaptive Prevention System

An intelligent, real-time security framework built with Python & Flask to detect and mitigate **Business Logic Vulnerabilities** and **API Sequence Abuse** in modern web applications.

---

## 🌟 Key Features

- **Real-Time Sequence Tracking**: Tracks the chronological order of API calls per session to ensure users follow legitimate business workflows (`login` ➔ `products` ➔ `add-to-cart` ➔ `checkout` ➔ `pay`).
- **State-Dependency Abuse Detection**: Automatically blocks out-of-order calls, direct checkout bypasses, payment skips, parameter tampering, and replayed requests.
- **Honeypot Endpoint Defense**: Traps and quarantines malicious bots probing hidden endpoints (`/api/admin_test`, `/api/debug`, `/api/internal`).
- **Adaptive Multi-Tier Mitigation**:
  - 📉 **Behavioral Trust Scoring** (0–100 scale)
  - ⏱️ **Progressive Cooldown Restrictions** (HTTP 429)
  - 🔒 **Dynamic Workflow Locking**
  - 🚦 **Adaptive Rate Limiting**
  - 🛡️ **Step-Up Authentication & Quarantine**
- **Email Verification & Security Notifications**: Real SMTP delivery over TLS (with Gmail App Password integration) for 6-digit registration OTPs and login alerts.
- **Interactive E-Commerce Storefront**: 20 products across 8 categories with 3D card flips, quantity steppers, live search, category filtering, and celebration animations.
- **Admin SOC Dashboard & Simulator**: Real-time KPI charts, audit logs, active threat tracking, and one-click attack simulations.

---

## 🏗️ Project Architecture

```
API_Call-Sequence-Abuse-Detection/
│
├── app.py                  # Main Flask Application & Route Controller
├── detector.py             # Rule-based Sequence Abuse Detection Engine
├── prevention.py           # Adaptive Mitigation & Behavioral State Engine
├── sequence_tracker.py     # In-memory API Sequence Tracker
├── logger.py               # Forensic CSV Audit Logger
│
├── templates/              # Jinja2 HTML Templates
│   ├── login.html
│   ├── register.html
│   ├── verify_email.html
│   ├── products.html
│   ├── cart.html
│   ├── checkout.html
│   ├── payment_success.html
│   ├── abuse_alert.html
│   ├── step_up.html
│   ├── dashboard.html
│   └── simulations.html
│
├── static/                 # Stylesheets & Static Assets
│   ├── style.css           # Custom Dark-Mode UI & 3D CSS
│   └── images/
│
├── .env.example            # Environment Variable Template
├── README_SMTP.md          # SMTP Setup Guide
└── requirements.txt        # Python Dependencies
```

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
cd YOUR_REPOSITORY_NAME
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables (Optional for SMTP)
Copy `.env.example` to `.env`:
```ini
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=your_email@gmail.com
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_16_char_app_password
```
*(Without `.env`, the app automatically falls back to local demo console mode.)*

### 4. Run the Application
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

- **User Demo**: Register an account with email verification and browse products.
- **Admin Dashboard**: Log in as `admin` / `chingu@325`.

---

## 🧪 Simulated Attack Scenarios

The built-in Attack Simulator allows testing common business logic exploits:
1. **Direct Checkout Bypass** (`login` ➔ `checkout`): Skips cart creation.
2. **Unauthenticated Access** (`products`): Invokes protected APIs before login.
3. **Payment Bypass** (`login` ➔ `products` ➔ `pay`): Attempts payment without checkout validation.
4. **Checkout Replay** (`login` ➔ `products` ➔ `add-to-cart` ➔ `checkout` ➔ `checkout`).
5. **Honeypot Probing** (`login` ➔ `admin-test`): Hits hidden trap routes.

---

## 📄 License
This project is licensed under the MIT License.
