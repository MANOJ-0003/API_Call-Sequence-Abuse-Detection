from collections import deque
from datetime import datetime, timedelta


INITIAL_TRUST_SCORE = 100
NORMAL_RATE_LIMIT = 100
SUSPICIOUS_RATE_LIMIT = 20
RATE_WINDOW_SECONDS = 60

user_security_state = {}


def get_user_state(user):
    if user not in user_security_state:
        user_security_state[user] = {
            "trust_score": INITIAL_TRUST_SCORE,
            "violations": 0,
            "workflow_locked": False,
            "quarantined": False,
            "session_revoked": False,
            "cooldown_until": None,
            "last_action": "Allow",
            "request_times": deque(),
            "baseline_fingerprint": None,
            "fingerprint_changes": 0,
            "step_up_verified": False,
        }

    return user_security_state[user]


def reset_user_state(user):
    state = get_user_state(user)
    state["workflow_locked"] = False
    state["quarantined"] = False
    state["session_revoked"] = False
    state["cooldown_until"] = None
    state["last_action"] = "Allow"
    state["step_up_verified"] = False
    state["request_times"].clear()


def get_cooldown_remaining(user):
    state = get_user_state(user)
    cooldown_until = state["cooldown_until"]

    if not cooldown_until:
        return 0

    remaining = (cooldown_until - datetime.now()).total_seconds()

    if remaining <= 0:
        state["cooldown_until"] = None
        return 0

    return int(remaining) + 1


def clear_user_state(user):
    user_security_state.pop(user, None)


def observe_behavior(user, fingerprint):
    """Track request velocity and a privacy-safe client fingerprint."""
    state = get_user_state(user)
    now = datetime.now()
    requests = state["request_times"]
    while requests and (now - requests[0]).total_seconds() >= RATE_WINDOW_SECONDS:
        requests.popleft()
    requests.append(now)

    if state["baseline_fingerprint"] is None:
        state["baseline_fingerprint"] = fingerprint
    elif fingerprint != state["baseline_fingerprint"]:
        state["fingerprint_changes"] += 1

    rate_limit = 0 if state["quarantined"] else (SUSPICIOUS_RATE_LIMIT if state["violations"] else NORMAL_RATE_LIMIT)
    return {
        "rate_limit": rate_limit,
        "requests_in_window": len(requests),
        "rate_limited": len(requests) > rate_limit,
        "fingerprint_changed": state["fingerprint_changes"] > 0,
    }


def requires_step_up(user, api_name):
    state = get_user_state(user)
    return api_name in {"checkout", "pay"} and state["violations"] > 0 and not state["step_up_verified"]


def verify_step_up(user):
    state = get_user_state(user)
    state["step_up_verified"] = True
    state["last_action"] = "Step-Up Verified"


def rate_limit_decision(user, behavior):
    state = get_user_state(user)
    state["last_action"] = "Adaptive Rate Limit"
    return {
        "action": "Adaptive Rate Limit", "blocked": True, "http_status": 429,
        "trust_score": state["trust_score"], "violations": state["violations"],
        "workflow_locked": state["workflow_locked"], "quarantined": state["quarantined"],
        "session_revoked": state["session_revoked"], "cooldown_seconds": 0,
        "rate_limit": behavior["rate_limit"],
        "message": f"Request blocked: {behavior['requests_in_window']} requests in one minute exceeds the adaptive limit of {behavior['rate_limit']}.",
    }


def _trust_penalty(risk):
    penalties = {
        "Low": 0,
        "Medium": 12,
        "High": 25,
        "Critical": 40,
    }

    return penalties.get(risk, 10)


def _risk_action(risk, violations, trust_score):
    if risk == "Critical" or trust_score < 40:
        return "Block + Quarantine"

    if risk == "High" or trust_score < 60 or violations >= 3:
        return "Workflow Lock"

    if risk == "Medium" and violations >= 2:
        return "Adaptive Cooldown"

    return "Warning"


def apply_prevention(user, analysis):
    state = get_user_state(user)

    if analysis["status"] == "Normal":
        state["last_action"] = "Allow"
        return {
            "action": "Allow",
            "blocked": False,
            "http_status": 200,
            "trust_score": state["trust_score"],
            "violations": state["violations"],
            "workflow_locked": state["workflow_locked"],
            "quarantined": state["quarantined"],
            "cooldown_seconds": 0,
            "message": "Request allowed by behavioral sequence validation.",
        }

    state["violations"] += 1
    state["trust_score"] = max(0, state["trust_score"] - _trust_penalty(analysis["risk"]))
    action = _risk_action(analysis["risk"], state["violations"], state["trust_score"])
    cooldown_seconds = min(20, 2 * state["violations"])

    if action == "Warning":
        http_status = 200
        blocked = False
        message = "The request was allowed with a warning, and the trust score was reduced for behavioral review."
    elif action == "Adaptive Cooldown":
        state["cooldown_until"] = datetime.now() + timedelta(seconds=cooldown_seconds)
        http_status = 429
        blocked = True
        message = "The request was blocked and a short cooldown was applied before the next attempt."
    elif action == "Workflow Lock":
        state["workflow_locked"] = True
        http_status = 403
        blocked = True
        message = "The request was blocked and the workflow was locked until the user restarts from login."
    elif action == "Block + Quarantine":
        state["workflow_locked"] = True
        state["quarantined"] = True
        state["session_revoked"] = True
        http_status = 403
        blocked = True
        message = "The request was blocked and the session was moved to quarantine mode."
    else:
        http_status = 403
        blocked = True
        message = "The request was blocked and the user received a sequence warning."

    state["last_action"] = action

    return {
        "action": action,
        "blocked": blocked,
        "http_status": http_status,
        "trust_score": state["trust_score"],
        "violations": state["violations"],
        "workflow_locked": state["workflow_locked"],
        "quarantined": state["quarantined"],
        "session_revoked": state["session_revoked"],
        "cooldown_seconds": cooldown_seconds if action == "Adaptive Cooldown" else 0,
        "rate_limit": 0 if state["quarantined"] else (SUSPICIOUS_RATE_LIMIT if state["violations"] else NORMAL_RATE_LIMIT),
        "message": message,
    }


def get_all_states():
    return user_security_state
