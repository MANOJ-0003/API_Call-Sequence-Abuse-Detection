# Abstract

## A Behavioral API Call-Sequence Analysis Framework for Detecting and Preventing Business Logic Abuse in Web Applications

Modern web applications rely heavily on APIs to support user workflows such as authentication, product browsing, cart management, checkout, and payment. This dependency makes them vulnerable to business logic abuse, where attackers misuse valid API requests in abnormal sequences instead of exploiting traditional software vulnerabilities. Conventional security mechanisms such as Web Application Firewalls and signature-based Intrusion Detection Systems mainly inspect individual requests, so they often fail to identify workflow bypass, direct endpoint access, replay attempts, and unauthorized API invocation.

This project presents a behavioral API call-sequence analysis framework for detecting and preventing business logic abuse in web applications. The framework monitors each user's API request order, compares the observed sequence with expected workflow rules, and identifies deviations in real time. It detects misuse scenarios such as checkout without cart creation, unauthenticated access to protected APIs, repeated checkout attempts, payment bypass, invalid product manipulation, and honeypot endpoint probing.

The system is implemented using Python and Flask with modules for API logging, per-user sequence tracking, behavioral validation, risk scoring, and prevention enforcement. Its prevention layer uses a sequence trust score, progressive risk-based response, workflow locking, session quarantine, adaptive cooldown, and security event logging. A dashboard visualizes API activity, suspicious requests, blocked attempts, risk distribution, trust state, and attack simulation results. By analyzing user behavior across API sequences instead of isolated requests, the framework provides a practical and proactive method for protecting API-driven web applications from workflow-based business logic abuse.

Word count: 236
