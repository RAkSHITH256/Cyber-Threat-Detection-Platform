import re
import requests
import tldextract
import json
import os
from urllib.parse import urlparse
from detectors.utils import get_domain, is_trusted, analyze_intent, get_category, get_verdict

def load_phishing_domains():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(base_dir, "data", "phishing_domains.json")
        with open(data_path, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

KNOWN_PHISHING_DOMAINS = load_phishing_domains()

def analyze_url(url):
    features = {}
    explanations = []
    mitigations = []
    risk_score = 0

    # 1. URL length
    features["url_length"] = len(url)
    if len(url) > 75:
        risk_score += 20
        explanations.append("URL is unusually long, which is common for obfuscation.")

    # 2. HTTPS check
    parsed = urlparse(url)
    features["uses_https"] = parsed.scheme == "https"
    if not features["uses_https"]:
        risk_score += 15
        explanations.append("URL does not use HTTPS, meaning connection is not secure.")
    else:
        mitigations.append("URL uses secure HTTPS protocol.")

    # 3. IP address in URL
    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    features["has_ip"] = bool(re.search(ip_pattern, url))
    if features["has_ip"]:
        risk_score += 30
        explanations.append("URL uses a raw IP address instead of a domain name.")

    # 4. Suspicious symbols
    features["symbol_count"] = url.count("-") + url.count("@")
    if features["symbol_count"] > 1:
        risk_score += 10
        explanations.append("URL contains multiple hyphens or '@' symbols, often used to mimic real domains.")

    # 5. Domain extraction
    domain = get_domain(url)
    features["domain"] = domain
    trusted = is_trusted(domain)
    features["is_trusted"] = trusted
    
    if trusted:
        risk_score -= 30
        mitigations.append(f"Domain '{domain}' is a recognized trusted brand.")
    
    # Check for phishing database
    if domain in KNOWN_PHISHING_DOMAINS:
        risk_score = 100
        features["database_match"] = True
        explanations.append("Domain is found in our database of known phishing sites.")
    
    # 6. Intent analysis (check path for keywords)
    intent = analyze_intent(url)
    has_credential_request = intent["has_credential_request"]
    features["credential_warning"] = has_credential_request
    if has_credential_request:
        risk_score += 25
        explanations.append(f"URL path seems to request sensitive actions: {', '.join(intent['matched_keywords'])}")
    else:
        mitigations.append("No sensitive action or credential request detected in URL path.")

    # Final logic adjustments
    risk_score = max(0, min(risk_score, 100))
    category = get_category(risk_score, has_credential_request, trusted)
    verdict = get_verdict(category)

    return {
        "risk_score": risk_score,
        "category": category,
        "verdict": verdict,
        "features": features,
        "explanations": explanations,
        "mitigations": mitigations
    }

