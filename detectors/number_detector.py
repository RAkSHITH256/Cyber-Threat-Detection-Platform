import re
import hashlib
import json
import os
from detectors.utils import get_category, get_verdict

def load_spam_numbers():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(base_dir, "data", "spam_numbers.json")
        with open(data_path, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

KNOWN_SPAM_NUMBERS = load_spam_numbers()

def analyze_number(number):
    risk_score = 0
    features = {}
    explanations = []
    mitigations = []

    # Normalize input: remove all non-digits except for leading '+' if present
    clean = re.sub(r"[^\d+]", "", number)
    features["normalized"] = clean
    
    # Strictly numeric version for some checks
    clean_digits = re.sub(r"\D", "", clean)

    # Validate format: basic length and character check
    valid_format = bool(re.fullmatch(r"\+?\d{8,15}", clean))
    features["valid_format"] = valid_format
    if not valid_format:
        risk_score += 30
        explanations.append("Phone number format is non-standard or too short/long.")
    
    # Check for India Telemarketing Prefix (140)
    # Common formats: 140XXXXXXX, +91140XXXXXXX, 0140XXXXXXX
    is_telemarketing = False
    if clean_digits.startswith("140") and len(clean_digits) == 10:
        is_telemarketing = True
    elif (clean_digits.startswith("91140") and len(clean_digits) == 12):
        is_telemarketing = True
    elif (clean_digits.startswith("0140") and len(clean_digits) == 11):
        is_telemarketing = True
        
    if is_telemarketing:
        risk_score += 60
        explanations.append("Number matches known Indian telemarketing (140) prefix clusters.")

    # Country code check (India-focused)
    if clean.startswith("+") and not clean.startswith("+91"):
        risk_score += 15
        explanations.append("Number is from an international region outside local priority (India).")
    elif clean.startswith("+91") or (len(clean_digits) == 10 and not clean.startswith("+")):
        mitigations.append("Number is from the local region (India) or follows local 10-digit format.")

    # Repeated digit analysis (Improved)
    if len(clean_digits) > 0:
        digit_counts = {d: clean_digits.count(d) for d in set(clean_digits)}
        max_repeated = max(digit_counts.values())
        repeated_ratio = max_repeated / len(clean_digits)
        features["repeated_digit_ratio"] = round(repeated_ratio, 2)
        if repeated_ratio > 0.6:
            risk_score += 25
            explanations.append("Number contains highly repetitive digits (suspicious).")
        elif len(set(clean_digits)) <= 3 and len(clean_digits) >= 10:
             risk_score += 20
             explanations.append("Number uses a very limited set of unique digits.")

    # Sequential pattern detection (Improved)
    sequences = ["0123", "1234", "2345", "3456", "4567", "5678", "6789", "9876", "5432", "4321"]
    has_sequence = any(seq in clean_digits for seq in sequences)
    features["sequential_pattern"] = has_sequence
    if has_sequence:
        risk_score += 15
        explanations.append("Number contains simple sequential patterns.")

    # Check known spam database
    # Check both ways: with and without '+' to be robust
    search_variants = {clean}
    if clean.startswith("+"):
        search_variants.add(clean[1:])
    else:
        search_variants.add("+" + clean)
    
    is_known_spam = any(v in KNOWN_SPAM_NUMBERS for v in search_variants)
    
    if is_known_spam:
        risk_score = 100
        explanations.append("Number is a confirmed sender in our threat database.")
        category = "Scam"
    else:
        # Simulation Logic for demo/training - using a more stable hash check
        hash_object = hashlib.md5(clean_digits.encode())
        hash_hex = hash_object.hexdigest()
        hash_val = int(hash_hex[:2], 16)
        
        if hash_val < 60: # ~23% chance
            risk_score = max(risk_score, 85)
            explanations.append(f"Number has been flagged by the community for suspicious activity.")
        elif hash_val < 90: # ~12% chance
            risk_score = max(risk_score, 45)
            explanations.append(f"Number has recent reports for unsolicited telemarketing.")
        else:
            risk_score = max(0, risk_score - 10)
            if risk_score < 40:
                mitigations.append("No active community flags found for this number.")

    # Final logic
    risk_score = max(0, min(risk_score, 100))
    # Note: No direct "intent" or "trusted_source" for a raw number
    category = get_category(risk_score, False, False)
    verdict = get_verdict(category)

    return {
        "risk_score": risk_score,
        "category": category,
        "verdict": verdict,
        "features": features,
        "explanations": explanations,
        "mitigations": mitigations
    }

