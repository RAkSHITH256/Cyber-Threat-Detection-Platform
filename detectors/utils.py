import json
import os
import tldextract
import re

def load_json_data(filename):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(base_dir, "data", filename)
        with open(data_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

TRUSTED_DOMAINS = load_json_data("trusted_domains.json").get("trusted_domains", [])
INTENT_KEYWORDS = load_json_data("intent_keywords.json").get("high_risk_intents", [])

def get_domain(url):
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return None

def is_trusted(url_or_domain):
    if not url_or_domain:
        return False
    domain = get_domain(url_or_domain) if "://" in url_or_domain or "." in url_or_domain else url_or_domain
    return domain in TRUSTED_DOMAINS

def analyze_intent(text):
    text_lower = text.lower()
    matches = [word for word in INTENT_KEYWORDS if word in text_lower]
    return {
        "has_credential_request": len(matches) > 0,
        "matched_keywords": matches
    }

def get_category(risk_score, has_credential_request, is_trusted_source):
    if is_trusted_source:
        if risk_score > 70:
            return "Suspicious" # Even trusted can be compromised or spoofed if score is very high
        return "Legitimate"
    
    if has_credential_request:
        if risk_score > 60:
            return "Scam"
        return "Suspicious"
    
    if risk_score > 70:
        return "Scam"
    if risk_score > 40:
        return "Suspicious"
    if risk_score > 15:
        return "Promotional"
    
    return "Legitimate"

def get_verdict(category):
    verdict_map = {
        "Legitimate": "SAFE (Verified/Safe)",
        "Promotional": "LOW RISK (Promotional)",
        "Suspicious": "MEDIUM RISK (Suspicious)",
        "Scam": "HIGH RISK (Scam/Phishing)"
    }
    return verdict_map.get(category, "UNKNOWN")
