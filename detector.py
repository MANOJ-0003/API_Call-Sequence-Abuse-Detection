def detect_abuse(sequence):

    if "checkout" in sequence and "add-to-cart" not in sequence:
        return "Abuse detected: Checkout without add-to-cart"

    if sequence.count("checkout") > 1:
        return "Abuse detected: Multiple checkout attempts"

    return "Normal"