import json
import os
import joblib
import re
from sklearn.pipeline import Pipeline
from detectors.utils import get_domain, is_trusted, analyze_intent, get_category, get_verdict

def load_spam_keywords():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_path = os.path.join(base_dir, "data", "spam_keywords.json")
        with open(data_path, "r") as f:
            return json.load(f)
    except Exception:
        return ["urgent", "winner", "verify"]

SPAM_KEYWORDS = load_spam_keywords()

_model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "spam_model.pkl")
if os.path.exists(_model_path):
    _spam_model: Pipeline = joblib.load(_model_path)
else:
    _spam_model = None

def analyze_message(message):
    features = {}
    explanations = []
    mitigations = []
    risk_score = 0
    
    # 1. AI Model Analysis
    if _spam_model is not None:
        prob = _spam_model.predict_proba([message])[0]
        spam_prob = prob[1]
        risk_score = int(spam_prob * 100)
        features["ai_spam_probability"] = spam_prob
        if spam_prob > 0.6:
            explanations.append(f"AI model identified patterns common in scam messages ({int(spam_prob*100)}% match).")
    else:
        # Fallback keyword matching
        message_lower = message.lower()
        keyword_matches = [word for word in SPAM_KEYWORDS if word in message_lower]
        features["keyword_matches"] = keyword_matches
        risk_score = len(keyword_matches) * 20
        if len(keyword_matches) > 0:
            explanations.append(f"Message contains suspicious keywords: {', '.join(keyword_matches)}")

    # 2. Intent Analysis
    intent = analyze_intent(message)
    has_credential_request = intent["has_credential_request"]
    features["credential_warning"] = has_credential_request
    if has_credential_request:
        risk_score += 20
        explanations.append(f"Message seems to request sensitive information or action: {', '.join(intent['matched_keywords'])}")
    else:
        risk_score -= 10
        mitigations.append("No direct request for OTPs, passwords, or logins detected.")

    # 3. Trusted Domain Check (if links are present)
    urls = re.findall(r'(https?://\S+)', message)
    features["contains_links"] = len(urls) > 0
    trusted_source = False
    if urls:
        all_trusted = True
        for url in urls:
            domain = get_domain(url)
            if is_trusted(domain):
                mitigations.append(f"Contains link to a trusted domain: {domain}")
            else:
                all_trusted = False
                explanations.append(f"Contains link to an untrusted or unknown domain: {domain}")
        
        if all_trusted:
            risk_score -= 20
            trusted_source = True
    
    # Final adjustments
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

