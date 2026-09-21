"""
benchmark.py
============
Runs controlled experiments against detector.py and prevention.py
to produce ground-truth values for TABLE II and TABLE III in the paper.

Each attack scenario is simulated with:
  - 50 POSITIVE trials (should be flagged)
  - 50 NEGATIVE trials (clean / normal sequences)

TP = positive trial correctly flagged as abuse
FP = negative trial incorrectly flagged as abuse
FN = positive trial missed (not flagged)
TN = negative trial correctly passed

Detection Rate = TP / (TP + FN)  [Recall / Sensitivity]
Precision      = TP / (TP + FP)
F1             = 2 * Precision * Recall / (Precision + Recall)
"""

import sys, os, importlib, datetime, json

# ── make sure we run from the project root ──────────────────────────────────
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from detector import analyze_abuse
from prevention import apply_prevention, get_user_state, user_security_state

# ─────────────────────────────────────────────────────────────────────────────
# SCENARIO DEFINITIONS
# Each entry: (name, positive_sequences, negative_sequences)
#   positive = sequences that SHOULD trigger abuse detection
#   negative = sequences that represent normal / benign behavior
# ─────────────────────────────────────────────────────────────────────────────

SCENARIOS = [

    # ── 1. Honeypot Probe ────────────────────────────────────────────────────
    ("Honeypot Probe",
     # Positive: access hidden internal endpoint
     [
         ["login", "admin-test"],
         ["login", "products", "debug"],
         ["login", "products", "add-to-cart", "internal"],
         ["admin-test"],
         ["debug"],
         ["login", "debug"],
         ["login", "internal"],
         ["login", "products", "internal"],
         ["login", "products", "add-to-cart", "admin-test"],
         ["login", "products", "add-to-cart", "checkout", "internal"],
     ] * 5,   # 50 trials
     # Negative: normal flows with NO honeypot calls
     [
         ["login", "products"],
         ["login", "products", "add-to-cart"],
         ["login", "products", "add-to-cart", "cart"],
         ["login", "products", "add-to-cart", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "pay"],
     ] * 10,  # 50 trials
    ),

    # ── 2. Payment Bypass ────────────────────────────────────────────────────
    ("Payment Bypass",
     [
         ["login", "pay"],
         ["login", "products", "pay"],
         ["login", "products", "add-to-cart", "pay"],
         ["pay"],
         ["login", "products", "add-to-cart", "cart", "pay"],
     ] * 10,
     [
         ["login", "products", "add-to-cart", "checkout", "pay"],
         ["login", "products", "add-to-cart", "cart", "checkout", "pay"],
     ] * 25,
    ),

    # ── 3. Checkout Bypass ───────────────────────────────────────────────────
    ("Checkout Bypass",
     [
         ["login", "checkout"],
         ["login", "products", "checkout"],
         ["login", "checkout", "pay"],
         ["login", "products", "checkout", "pay"],
         ["checkout"],
         ["login", "products", "cart", "checkout"],
     ] * 8 + [["login", "checkout"]] * 2,
     [
         ["login", "products", "add-to-cart", "checkout"],
         ["login", "products", "add-to-cart", "cart", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "pay"],
     ] * 17,
    ),

    # ── 4. Unauthenticated Access ────────────────────────────────────────────
    ("Unauth. Access",
     [
         ["products"],
         ["cart"],
         ["add-to-cart"],
         ["checkout"],
         ["pay"],
         ["products", "add-to-cart"],
         ["products", "cart"],
         ["products", "add-to-cart", "checkout"],
         ["products", "add-to-cart", "checkout", "pay"],
         ["cart", "checkout"],
     ] * 5,
     [
         ["login", "products"],
         ["login", "products", "add-to-cart"],
         ["login", "products", "add-to-cart", "cart"],
         ["login", "products", "add-to-cart", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "pay"],
     ] * 10,
    ),

    # ── 5. Out-of-Order Cart ─────────────────────────────────────────────────
    ("Out-of-Order Cart",
     [
         ["login", "cart"],
         ["login", "add-to-cart"],
         ["login", "cart", "checkout"],
         ["login", "add-to-cart", "checkout"],
         ["login", "cart", "add-to-cart", "checkout"],
     ] * 10,
     [
         ["login", "products", "add-to-cart"],
         ["login", "products", "add-to-cart", "cart"],
         ["login", "products", "cart"],
         ["login", "products", "add-to-cart", "cart", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "pay"],
     ] * 10,
    ),

    # ── 6. Checkout Replay ───────────────────────────────────────────────────
    ("Checkout Replay",
     [
         ["login", "products", "add-to-cart", "checkout", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "checkout", "pay"],
         ["login", "products", "add-to-cart", "checkout", "checkout", "checkout"],
     ] * 17,
     [
         ["login", "products", "add-to-cart", "checkout"],
         ["login", "products", "add-to-cart", "checkout", "pay"],
     ] * 25,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Prevention mechanism triggers — tracked across all sessions
# ─────────────────────────────────────────────────────────────────────────────

prevention_counts = {
    "Rate Throttling":    {"triggered": 0, "successful": 0},
    "Cooldown":           {"triggered": 0, "successful": 0},
    "Workflow Locking":   {"triggered": 0, "successful": 0},
    "Step-Up Verification": {"triggered": 0, "successful": 0},
    "Session Quarantine": {"triggered": 0, "successful": 0},
    "Session Revocation": {"triggered": 0, "successful": 0},
}

def run_scenario(name, positives, negatives):
    TP = FP = FN = TN = 0
    fake_user = f"bench_{name.replace(' ', '_').lower()}"

    # --- positive trials (expected: Abuse Detected) ---
    for seq in positives:
        result = analyze_abuse(seq)
        detected = result["status"] == "Abuse Detected"
        if detected:
            TP += 1
            # also track prevention actions
            prevention = apply_prevention(fake_user + "_pos", result)
            action = prevention["action"]
            if "Rate" in action or "rate" in action:
                prevention_counts["Rate Throttling"]["triggered"] += 1
                prevention_counts["Rate Throttling"]["successful"] += 1 if prevention["blocked"] else 0
            if "Cooldown" in action or "cooldown" in action.lower():
                prevention_counts["Cooldown"]["triggered"] += 1
                prevention_counts["Cooldown"]["successful"] += 1 if prevention["blocked"] else 0
            if "Workflow Lock" in action:
                prevention_counts["Workflow Locking"]["triggered"] += 1
                prevention_counts["Workflow Locking"]["successful"] += 1 if prevention.get("workflow_locked") else 0
            if prevention.get("quarantined"):
                prevention_counts["Session Quarantine"]["triggered"] += 1
                prevention_counts["Session Quarantine"]["successful"] += 1
            if prevention.get("session_revoked"):
                prevention_counts["Session Revocation"]["triggered"] += 1
                prevention_counts["Session Revocation"]["successful"] += 1
        else:
            FN += 1

    # --- negative trials (expected: Normal) ---
    for seq in negatives:
        result = analyze_abuse(seq)
        detected = result["status"] == "Abuse Detected"
        if detected:
            FP += 1
        else:
            TN += 1

    precision = TP / (TP + FP) if (TP + FP) > 0 else 1.0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    det_rate  = recall * 100

    return {
        "name": name,
        "TP": TP, "FP": FP, "FN": FN, "TN": TN,
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "det_rate":  round(det_rate, 2),
        "f1":        round(f1, 4),
    }


# ─────────────────────────────────────────────────────────────────────────────
# RUN ALL SCENARIOS
# ─────────────────────────────────────────────────────────────────────────────

print("=" * 70)
print("  API SENTINEL — BENCHMARK EVALUATION")
print(f"  Run at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 70)

results = []
total_tp = total_fp = total_fn = total_tn = 0

for name, positives, negatives in SCENARIOS:
    r = run_scenario(name, positives, negatives)
    results.append(r)
    total_tp += r["TP"]
    total_fp += r["FP"]
    total_fn += r["FN"]
    total_tn += r["TN"]

# Overall
ov_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
ov_recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
ov_f1        = 2 * ov_precision * ov_recall / (ov_precision + ov_recall) if (ov_precision + ov_recall) > 0 else 0.0

# ─── TABLE II ────────────────────────────────────────────────────────────────
print("\n TABLE II — Detection Performance by Attack Type")
print("-" * 70)
header = f"{'Attack':<22} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'Precision':>10} {'Recall':>8} {'Det.Rate':>10} {'F1':>7}"
print(header)
print("-" * 70)

for r in results:
    print(f"{r['name']:<22} {r['TP']:>4} {r['FP']:>4} {r['FN']:>4} {r['TN']:>4}"
          f" {r['precision']:>10.4f} {r['recall']:>8.4f} {r['det_rate']:>9.2f}% {r['f1']:>7.4f}")

print("-" * 70)
print(f"{'Overall':<22} {total_tp:>4} {total_fp:>4} {total_fn:>4} {total_tn:>4}"
      f" {ov_precision:>10.4f} {ov_recall:>8.4f} {ov_recall*100:>9.2f}% {ov_f1:>7.4f}")

# ─── TABLE III ───────────────────────────────────────────────────────────────
print("\n\n TABLE III — Adaptive Prevention Results")
print("-" * 50)
print(f"{'Mitigation':<25} {'Triggered':>10} {'Successful':>12}")
print("-" * 50)
for mech, counts in prevention_counts.items():
    print(f"{mech:<25} {counts['triggered']:>10} {counts['successful']:>12}")
print("-" * 50)

# ─── JSON EXPORT ────────────────────────────────────────────────────────────
export = {
    "table_ii": results,
    "table_ii_overall": {
        "TP": total_tp, "FP": total_fp, "FN": total_fn, "TN": total_tn,
        "precision": round(ov_precision, 4),
        "recall":    round(ov_recall, 4),
        "det_rate":  round(ov_recall * 100, 2),
        "f1":        round(ov_f1, 4),
    },
    "table_iii": prevention_counts,
}

out_path = os.path.join(ROOT, "benchmark_results.json")
with open(out_path, "w") as f:
    json.dump(export, f, indent=2)

print(f"\n[✓] Results saved to: {out_path}")
