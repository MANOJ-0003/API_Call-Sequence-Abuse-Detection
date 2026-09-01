# 📧 SMTP Email Setup Guide

This project sends two types of automated emails:
| Email | When sent |
|---|---|
| **Registration OTP** | During sign-up to verify the email address |
| **Login Notification** | Every time an authenticated user logs in |

By default the app runs in **demo / console mode** — codes and alerts are printed to the terminal instead of emailed.  
To send real emails, set the environment variables described below.

---

## ✅ Option 1 — Gmail (Free, Recommended)

### Step 1 — Enable 2-Step Verification
1. Go to <https://myaccount.google.com/security>
2. Click **2-Step Verification** → turn it **On**

### Step 2 — Create an App Password
1. Still on the Security page, click **App passwords**  
   *(or go to <https://myaccount.google.com/apppasswords>)*
2. Select app: **Mail** — Select device: **Other (Custom name)** → type `API Sentinel`
3. Click **Generate** — copy the **16-character password** shown

### Step 3 — Set Environment Variables

#### Windows (PowerShell — current session only)
```powershell
$env:SMTP_HOST      = "smtp.gmail.com"
$env:SMTP_PORT      = "587"
$env:SMTP_USE_TLS   = "true"
$env:SMTP_FROM      = "you@gmail.com"
$env:SMTP_USERNAME  = "you@gmail.com"
$env:SMTP_PASSWORD  = "abcd efgh ijkl mnop"   # 16-char App Password (spaces OK)
```

#### Windows (System-level — permanent)
```powershell
[System.Environment]::SetEnvironmentVariable("SMTP_HOST",     "smtp.gmail.com",    "User")
[System.Environment]::SetEnvironmentVariable("SMTP_PORT",     "587",               "User")
[System.Environment]::SetEnvironmentVariable("SMTP_USE_TLS",  "true",              "User")
[System.Environment]::SetEnvironmentVariable("SMTP_FROM",     "you@gmail.com",     "User")
[System.Environment]::SetEnvironmentVariable("SMTP_USERNAME", "you@gmail.com",     "User")
[System.Environment]::SetEnvironmentVariable("SMTP_PASSWORD", "abcdefghijklmnop",  "User")
```
*(Restart your terminal or IDE after setting system variables.)*

#### Using a `.env` file (python-dotenv)
Copy `.env.example` → `.env` and fill in the values:
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=you@gmail.com
SMTP_USERNAME=you@gmail.com
SMTP_PASSWORD=abcdefghijklmnop
```
Then install and load dotenv:
```powershell
pip install python-dotenv
```
Add to the top of `app.py` (before other imports):
```python
from dotenv import load_dotenv
load_dotenv()
```

### Step 4 — Restart and Test
```powershell
python app.py
```
Register a new account with your email address — you should receive the OTP email.  
Log in — you should receive a login-notification email.

---

## ✅ Option 2 — Outlook / Hotmail

```
SMTP_HOST=smtp-mail.outlook.com
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=you@outlook.com
SMTP_USERNAME=you@outlook.com
SMTP_PASSWORD=your-outlook-password
```

---

## ✅ Option 3 — Mailgun (Production Grade)

1. Sign up at <https://www.mailgun.com> (free tier: 100 emails/day)
2. Go to **Sending → Domains** and add/verify your domain
3. Under the domain, find **SMTP credentials**

```
SMTP_HOST=smtp.mailgun.org
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=noreply@yourdomain.com
SMTP_USERNAME=postmaster@yourdomain.com
SMTP_PASSWORD=your-mailgun-smtp-password
```

---

## ✅ Option 4 — SendGrid

1. Sign up at <https://sendgrid.com> (free tier: 100 emails/day)
2. Go to **Settings → API Keys** → Create API Key (Full Access)
3. Go to **Settings → Sender Authentication** and verify your sender email

```
SMTP_HOST=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_FROM=you@yourdomain.com
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.xxxxxxxxxxxxxxxxxxxx   # your SendGrid API key
```

---

## 🔍 Troubleshooting

| Problem | Fix |
|---|---|
| `SMTPAuthenticationError` | Wrong password, or App Password not created correctly |
| `SMTPConnectError` | Firewall blocking port 587 — try port 465 with `SMTP_USE_TLS=false` |
| Email goes to Spam | Verify sender domain / use Mailgun or SendGrid with SPF/DKIM |
| Still seeing console output | Check that env vars are set in the **same** terminal session running `app.py` |

---

## 🔒 Security Notes

- **Never** commit your real password or API key to git — add `.env` to `.gitignore`
- Use Gmail **App Passwords** (not your account password) for SMTP access
- In production, rotate SMTP credentials regularly
