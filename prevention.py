from collections import deque
from datetime import datetime, timedelta


# ─── Rate limit tiers (requests / minute) ───────────────────────────────────
RATE_NORMAL      = 100   # trust 80-100
RATE_SUSPICIOUS  = 20    # trust 50-79
RATE_HIGH_RISK   = 5     # trust  0-49
RATE_QUARANTINED = 0     # quarantine → all blocked

RATE_WINDOW_SECONDS = 60
INITIAL_TRUST       = 100

# ─── Progressive cooldown durations (seconds) ───────────────────────────────
COOLDOWN_TIERS = [5, 15, 30]          # violation 1 → 5s, 2 → 15s, 3+ → 30s

# ─── Trust penalty per risk level ───────────────────────────────────────────
TRUST_PENALTIES = {
    "Low":      0,
    "Medium":  12,
    "High":    25,
    "Critical": 40,
}

# ─── Attack-title → Prevention action map ────────────────────────────────────
# Maps each specific attack title to its intended prevention mechanism so that
# the engine applies the RIGHT action for EACH attack type rather than a generic
# risk-level lookup.
ATTACK_PREVENTION_MAP = {
    # Critical attacks
    "Honeypot API Probe":              "Block + Quarantine + Revoke",
    "Payment API Bypass":              "Block + Quarantine",
    # High attacks
    "Business-State Dependency Violation": "Workflow Lock",
    "Checkout Bypass Attempt":         "Workflow Lock",
    "Unauthenticated Workflow Access": "Block + Workflow Lock",
    # Medium attacks
    "Cart Step Invoked Out of Order":  "Warning + Cooldown",
    "Repeated Checkout Attempt":       "Cooldown + Workflow Lock",
    # Rate / session
    "Adaptive Rate Limit Exceeded":    "Adaptive Rate Limit",
    "Adaptive Cooldown Active":        "Cooldown",
    "Workflow Locked":                 "Block + Workflow Lock",
}

user_security_state = {}


# ─── State management ─────────────────────────────────────────────────────────

def get_user_state(user):
    if user not in user_security_state:
        user_security_state[user] = {
            "trust_score":          INITIAL_TRUST,
            "violations":           0,
            "workflow_locked":      False,
            "quarantined":          False,
            "session_revoked":      False,
            "cooldown_until":       None,
            "cooldown_tier":        0,        # tracks which tier is active (0-indexed)
            "last_action":          "Allow",
            "last_prevention_name": None,     # human-readable mechanism name
            "request_times":        deque(),
            "baseline_fingerprint": None,
            "fingerprint_changes":  0,
            "step_up_verified":     False,
        }
    return user_security_state[user]


def reset_user_state(user):
    state = get_user_state(user)
    state["workflow_locked"]      = False
    state["quarantined"]          = False
    state["session_revoked"]      = False
    state["cooldown_until"]       = None
    state["cooldown_tier"]        = 0
    state["last_action"]          = "Allow"
    state["last_prevention_name"] = None
    state["step_up_verified"]     = False
    state["request_times"].clear()


def clear_user_state(user):
    user_security_state.pop(user, None)


def get_all_states():
    return user_security_state


# ─── Cooldown ─────────────────────────────────────────────────────────────────

def get_cooldown_remaining(user):
    state = get_user_state(user)
    until = state["cooldown_until"]
    if not until:
        return 0
    remaining = (until - datetime.now()).total_seconds()
    if remaining <= 0:
        state["cooldown_until"] = None
        return 0
    return int(remaining) + 1


def _next_cooldown_seconds(state):
    """Return the next progressive cooldown duration and advance the tier."""
    tier_idx = min(state["cooldown_tier"], len(COOLDOWN_TIERS) - 1)
    state["cooldown_tier"] = tier_idx + 1
    return COOLDOWN_TIERS[tier_idx]


# ─── Behavioral observation (rate limiting) ───────────────────────────────────

def _rate_limit_for_state(state):
    if state["quarantined"]:
        return RATE_QUARANTINED
    trust = state["trust_score"]
    if trust >= 80:
        return RATE_NORMAL
    if trust >= 50:
        return RATE_SUSPICIOUS
    return RATE_HIGH_RISK


def observe_behavior(user, fingerprint):
    state = get_user_state(user)
    now = datetime.now()

    # Slide the request-time window
    rts = state["request_times"]
    while rts and (now - rts[0]).total_seconds() >= RATE_WINDOW_SECONDS:
        rts.popleft()
    rts.append(now)

    # Fingerprint drift detection
    if state["baseline_fingerprint"] is None:
        state["baseline_fingerprint"] = fingerprint
    elif fingerprint != state["baseline_fingerprint"]:
        state["fingerprint_changes"] += 1

    rate_limit = _rate_limit_for_state(state)
    return {
        "rate_limit":        rate_limit,
        "requests_in_window": len(rts),
        "rate_limited":      len(rts) > rate_limit,
        "fingerprint_changed": state["fingerprint_changes"] > 0,
    }


def rate_limit_decision(user, behavior):
    state = get_user_state(user)
    state["last_action"]          = "Adaptive Rate Limit"
    state["last_prevention_name"] = "Rate Throttling"
    return {
        "action":           "Adaptive Rate Limit",
        "prevention_name":  "Rate Throttling",
        "blocked":          True,
        "http_status":      429,
        "trust_score":      state["trust_score"],
        "violations":       state["violations"],
        "workflow_locked":  state["workflow_locked"],
        "quarantined":      state["quarantined"],
        "session_revoked":  state["session_revoked"],
        "cooldown_seconds": 0,
        "rate_limit":       behavior["rate_limit"],
        "message": (
            f"Adaptive rate limit exceeded: {behavior['requests_in_window']} requests in "
            f"60 seconds. Current limit is {behavior['rate_limit']} req/min based on "
            f"trust score {state['trust_score']}."
        ),
    }


# ─── Step-up verification ─────────────────────────────────────────────────────

def requires_step_up(user, api_name):
    state = get_user_state(user)
    return (
        api_name in {"checkout", "pay"}
        and state["violations"] > 0
        and not state["step_up_verified"]
        and not state["workflow_locked"]
        and not state["quarantined"]
    )


def verify_step_up(user):
    state = get_user_state(user)
    state["step_up_verified"]     = True
    state["last_action"]          = "Step-Up Verified"
    state["last_prevention_name"] = "Step-Up Verification"


# ─── Core prevention engine ───────────────────────────────────────────────────

def apply_prevention(user, analysis):
    """
    Apply the correct prevention mechanism based on:
      1. The specific attack title (ATTACK_PREVENTION_MAP)
      2. The risk level + current trust score + violation count

    Returns a dict describing the action taken.
    """
    state = get_user_state(user)

    # ── Normal flow: allow immediately ───────────────────────────────────────
    if analysis["status"] == "Normal":
        state["last_action"]          = "Allow"
        state["last_prevention_name"] = None
        return {
            "action":           "Allow",
            "prevention_name":  None,
            "blocked":          False,
            "http_status":      200,
            "trust_score":      state["trust_score"],
            "violations":       state["violations"],
            "workflow_locked":  state["workflow_locked"],
            "quarantined":      state["quarantined"],
            "session_revoked":  state["session_revoked"],
            "cooldown_seconds": 0,
            "message":          "Request allowed by behavioral sequence validation.",
        }

    # ── Violation bookkeeping ─────────────────────────────────────────────────
    state["violations"] += 1
    penalty = TRUST_PENALTIES.get(analysis["risk"], 10)
    state["trust_score"] = max(0, state["trust_score"] - penalty)

    title  = analysis.get("title", "")
    risk   = analysis["risk"]
    trust  = state["trust_score"]
    viols  = state["violations"]

    # ── Determine action from attack-title map ────────────────────────────────
    mapped = ATTACK_PREVENTION_MAP.get(title)

    # Fall back to risk-level heuristic when title is not in map
    if mapped is None:
        if risk == "Critical" or trust < 40:
            mapped = "Block + Quarantine + Revoke"
        elif risk == "High" or trust < 60 or viols >= 3:
            mapped = "Workflow Lock"
        elif risk == "Medium" and viols >= 2:
            mapped = "Cooldown + Workflow Lock"
        elif risk == "Medium":
            mapped = "Warning + Cooldown"
        else:
            mapped = "Warning"

    # ── Execute the mapped prevention action ──────────────────────────────────
    blocked         = True
    http_status     = 403
    cooldown_secs   = 0
    prevention_name = mapped

    if mapped == "Warning":
        blocked          = False
        http_status      = 200
        prevention_name  = "Warning"
        message = "Request allowed with a warning. Trust score reduced for behavioral monitoring."

    elif mapped == "Warning + Cooldown":
        cooldown_secs    = _next_cooldown_seconds(state)
        state["cooldown_until"] = datetime.now() + timedelta(seconds=cooldown_secs)
        http_status      = 429
        prevention_name  = "Cooldown"
        message = (
            f"Progressive cooldown applied: {cooldown_secs}s restriction "
            f"(violation {viols} of 3 tiers). Retry after cooldown expires."
        )

    elif mapped == "Cooldown + Workflow Lock":
        cooldown_secs    = _next_cooldown_seconds(state)
        state["cooldown_until"]  = datetime.now() + timedelta(seconds=cooldown_secs)
        state["workflow_locked"] = True
        http_status      = 429
        prevention_name  = "Cooldown + Workflow Lock"
        message = (
            f"Cooldown ({cooldown_secs}s) applied and workflow locked after repeated "
            f"sequence violation (violation {viols}). Restart from login after cooldown."
        )

    elif mapped == "Workflow Lock":
        state["workflow_locked"] = True
        prevention_name  = "Workflow Locking"
        message = (
            "Workflow locked: invalid business-state transition detected. "
            "User must restart the workflow from login."
        )

    elif mapped == "Block + Workflow Lock":
        state["workflow_locked"] = True
        prevention_name  = "Workflow Locking"
        message = (
            "Request blocked and workflow locked: access to protected APIs "
            "requires a valid authenticated session."
        )

    elif mapped == "Block + Quarantine":
        state["workflow_locked"] = True
        state["quarantined"]     = True
        prevention_name  = "Session Quarantine"
        message = (
            "Session quarantined: critical workflow violation detected. "
            "Sensitive API access is suspended for this session."
        )

    elif mapped == "Block + Quarantine + Revoke":
        state["workflow_locked"] = True
        state["quarantined"]     = True
        state["session_revoked"] = True
        prevention_name  = "Session Revocation"
        message = (
            "Session revoked: honeypot endpoint access detected. "
            "The session has been invalidated and all workflow operations are blocked."
        )

    elif mapped == "Adaptive Rate Limit":
        http_status      = 429
        prevention_name  = "Rate Throttling"
        message = "Request blocked by adaptive rate limiter."

    else:
        # Generic block fallback
        prevention_name  = "Block"
        message = "Request blocked by prevention engine."

    state["last_action"]          = mapped
    state["last_prevention_name"] = prevention_name

    return {
        "action":           mapped,
        "prevention_name":  prevention_name,
        "blocked":          blocked,
        "http_status":      http_status,
        "trust_score":      state["trust_score"],
        "violations":       state["violations"],
        "workflow_locked":  state["workflow_locked"],
        "quarantined":      state["quarantined"],
        "session_revoked":  state.get("session_revoked", False),
        "cooldown_seconds": cooldown_secs,
        "rate_limit":       _rate_limit_for_state(state),
        "message":          message,
    }
