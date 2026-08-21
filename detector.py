def analyze_abuse(sequence):

    expected_checkout_flow = ["login", "products", "add-to-cart", "checkout", "pay"]
    protected_apis = ["products", "cart", "add-to-cart", "checkout", "pay"]
    api_dependencies = {
        "cart": ["products"],
        "add-to-cart": ["products"],
        "checkout": ["add-to-cart"],
        "pay": ["checkout"],
    }
    current_api = sequence[-1] if sequence else None

    if current_api in ["admin-test", "debug", "internal"]:
        return {
            "status": "Abuse Detected",
            "title": "Honeypot API Probe",
            "risk": "Critical",
            "risk_score": 98,
            "summary": "The user accessed a hidden internal endpoint that is never used by normal application workflows.",
            "reason": "Honeypot APIs help detect endpoint probing and automated discovery attempts because legitimate users cannot reach these routes from the UI.",
            "violated_rule": "hidden internal APIs must not be requested",
            "missing_step": None,
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Block the request immediately, quarantine the session, and alert the administrator.",
        }

    if current_api in protected_apis and "login" not in sequence:
        return {
            "status": "Abuse Detected",
            "title": "Unauthenticated Workflow Access",
            "risk": "High",
            "risk_score": 82,
            "summary": "The user attempted to access a protected workflow API before completing the login step.",
            "reason": "Business workflows should begin with a valid login event. Direct access to protected APIs may indicate URL tampering or scripted endpoint access.",
            "violated_rule": "protected APIs require a previous login event",
            "missing_step": "login",
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Block the request, lock the workflow, and require the user to restart from login.",
        }

    # Business-state validation is deliberately expressed as API dependencies,
    # rather than only endpoint authorization. This prevents a caller from
    # jumping into a later commerce state by invoking its URL directly.
    required_steps = api_dependencies.get(current_api, [])
    missing_steps = [step for step in required_steps if step not in sequence[:-1]]
    if missing_steps:
        missing_step = missing_steps[0]
        risk = "Critical" if current_api == "pay" else "High" if current_api == "checkout" else "Medium"
        score = {"Medium": 64, "High": 86, "Critical": 94}[risk]
        return {
            "status": "Abuse Detected",
            "title": "Business-State Dependency Violation",
            "risk": risk,
            "risk_score": score,
            "summary": f"The {current_api} API was requested before the required {missing_step} business state existed.",
            "reason": "Sensitive APIs must follow their declared business-state dependencies, even when the caller is authenticated.",
            "violated_rule": f"{current_api} requires a previous {missing_step} event",
            "missing_step": missing_step,
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Block the request and require the user to resume the workflow from the missing step.",
        }

    if current_api == "cart" and "products" not in sequence:
        return {
            "status": "Abuse Detected",
            "title": "Cart Step Invoked Out of Order",
            "risk": "Medium",
            "risk_score": 62,
            "summary": "The cart API was requested before the product listing step was completed.",
            "reason": "A normal shopping workflow requires product browsing before the cart is viewed or modified.",
            "violated_rule": "cart requires a previous products event",
            "missing_step": "products",
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Warn the user and redirect the workflow to the product listing step.",
        }

    if "checkout" in sequence and "add-to-cart" not in sequence:
        return {
            "status": "Abuse Detected",
            "title": "Checkout Bypass Attempt",
            "risk": "High",
            "risk_score": 85,
            "summary": "The user attempted to access checkout without first adding an item to the cart.",
            "reason": "In a normal commerce workflow, checkout should only happen after a cart is created. A direct checkout request can indicate API sequence abuse, endpoint probing, or an attempt to bypass business rules.",
            "violated_rule": "checkout requires a previous add-to-cart event",
            "missing_step": "add-to-cart",
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Block the checkout request, keep the event in the audit log, and ask the user to restart from the product/cart flow.",
        }

    if sequence.count("checkout") > 1:
        return {
            "status": "Abuse Detected",
            "title": "Repeated Checkout Attempt",
            "risk": "Medium",
            "risk_score": 70,
            "summary": "The same session attempted checkout more than once in the tracked workflow.",
            "reason": "Multiple checkout calls in one sequence may signal replay behavior, duplicate payment attempts, or automation repeatedly hitting a sensitive endpoint.",
            "violated_rule": "checkout should appear only once before the sequence resets",
            "missing_step": None,
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Pause the request, review the session activity, and reset the workflow before allowing another checkout.",
        }

    if current_api == "pay" and "checkout" not in sequence:
        return {
            "status": "Abuse Detected",
            "title": "Payment API Bypass",
            "risk": "Critical",
            "risk_score": 94,
            "summary": "The payment API was requested before the checkout step was validated.",
            "reason": "Payment should only be reachable after the system validates the cart and checkout workflow.",
            "violated_rule": "pay requires a previous checkout event",
            "missing_step": "checkout",
            "expected_flow": expected_checkout_flow,
            "observed_flow": sequence,
            "recommendation": "Block the request, quarantine the session, and log the event as a critical workflow bypass.",
        }

    return {
        "status": "Normal",
        "title": "Normal API Sequence",
        "risk": "Low",
        "risk_score": 10,
        "summary": "No abuse pattern was detected.",
        "reason": "The observed API sequence matches the expected workflow rules.",
        "violated_rule": None,
        "missing_step": None,
        "expected_flow": expected_checkout_flow,
        "observed_flow": sequence,
        "recommendation": "Allow the request.",
    }


def detect_abuse(sequence):

    analysis = analyze_abuse(sequence)

    if analysis["status"] == "Normal":
        return "Normal"

    return f"Abuse detected: {analysis['title']}"
