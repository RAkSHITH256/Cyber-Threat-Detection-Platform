import re
import json
import os
from detectors.utils import get_domain, is_trusted, analyze_intent, get_category, get_verdict
from .url_detector import KNOWN_PHISHING_DOMAINS
from .message_detector import SPAM_KEYWORDS

def analyze_email(content):
    risk_score = 0
    features = {}
    explanations = []
    mitigations = []
    content_lower = content.lower()

    # 1. Intent Analysis
    intent = analyze_intent(content)
    has_credential_request = intent["has_credential_request"]
    features["credential_warning"] = has_credential_request
    if has_credential_request:
        risk_score += 30
        explanations.append(f"Email requests sensitive actions: {', '.join(intent['matched_keywords'])}")
    else:
        risk_score -= 10
        mitigations.append("No credential requests (OTP/Password) detected in body.")

    # 2. Trusted Domain Check (Links in email)
    urls = re.findall(r'(https?://\S+)', content)
    trusted_source = False
    if urls:
        all_trusted = True
        for url in urls:
            domain = get_domain(url)
            if is_trusted(domain):
                mitigations.append(f"Contains link to trusted domain: {domain}")
            else:
                all_trusted = False
                explanations.append(f"Contains link to untrusted domain: {domain}")
                # Check known phishing database
                if domain in KNOWN_PHISHING_DOMAINS:
                    risk_score += 50
                    explanations.append(f"Domain '{domain}' is a confirmed phishing host.")
        
        if all_trusted:
            risk_score -= 20
            trusted_source = True
    else:
        mitigations.append("No external links found in the email.")

    # 3. Content Patterns
    keyword_matches = [word for word in SPAM_KEYWORDS if word in content_lower]
    if len(keyword_matches) > 1:
        risk_score += 20
        explanations.append(f"Typical spam language detected: {', '.join(keyword_matches)}")
    
    # Generic Greeting
    if any(greeting in content_lower[:100] for greeting in ["dear customer", "dear user", "dear member"]):
        risk_score += 15
        explanations.append("Uses a generic greeting ('Dear Customer'), common in phishing.")
    else:
        mitigations.append("Does not use common generic greetings.")

    # Final logic
    risk_score = max(0, min(risk_score, 100))
    category = get_category(risk_score, has_credential_request, trusted_source)
    verdict = get_verdict(category)

    return {
        "risk_score": risk_score,
        "category": category,
        "verdict": verdict,
        "features": features,
        "explanations": explanations,
        "mitigations": mitigations
    }

