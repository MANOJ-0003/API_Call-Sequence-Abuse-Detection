# Project Completion Notes

## Title

A Behavioral API Call-Sequence Analysis Framework for Detecting and Preventing Business Logic Abuse in Web Applications

## Completed Modules

- Flask e-commerce workflow: login, products, add to cart, cart, checkout, payment, logout.
- API request logging in `api_logs.csv`.
- Per-user API sequence tracking.
- Behavioral validation for valid and invalid API order.
- Abuse detection rules for checkout bypass, unauthenticated access, cart misuse, repeated checkout, payment bypass, invalid products, and honeypot API probing.
- Prevention engine with sequence trust score, progressive response, adaptive cooldown, workflow lock, session quarantine, and blocked security event logging.
- Admin dashboard with total requests, suspicious requests, blocked attempts, detection rate, risk distribution, prevention actions, user trust state, security events, and recent API logs.
- Attack simulation page with normal and malicious scenario matrix.
- Final abstract for the report.

## Unique Prevention Mechanism

The project uses a combined prevention strategy instead of only returning a basic block response:

- Sequence Trust Score: each user starts with a trust score of 100, and suspicious behavior reduces the score according to risk.
- Progressive Risk-Based Response: medium-risk behavior receives cooldown, high-risk behavior locks the workflow, and critical behavior quarantines the session.
- Dynamic Workflow Lock: users who violate workflow rules must restart from login before continuing protected operations.
- Session Quarantine: critical attacks such as payment bypass or honeypot probing place the session into a restricted state.
- Honeypot APIs: hidden endpoints such as `/api/admin_test`, `/api/debug`, and `/api/internal` identify probing behavior.

## Demo Flow

Normal flow:

`/` -> login -> products -> add-to-cart -> checkout -> pay

Attack examples:

- `/checkout?user=attacker`
- `/pay?user=attacker`
- `/api/admin_test?user=attacker`
- `/products?user=direct-user`

Open `/dashboard` to view security events and `/simulate-attacks` to show the prepared evaluation scenarios.

## Testing Checklist

- Verify normal purchase completes successfully.
- Verify direct checkout is blocked.
- Verify direct payment is blocked.
- Verify direct protected API access without login is blocked.
- Verify repeated checkout is detected.
- Verify invalid product tampering is blocked.
- Verify honeypot API access is logged as critical risk.
- Verify dashboard counters and security event table update after attacks.
