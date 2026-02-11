import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from detectors.url_detector import analyze_url
from detectors.message_detector import analyze_message
from detectors.number_detector import analyze_number
from detectors.email_detector import analyze_email

def run_test(name, result):
    print(f"--- TEST: {name} ---")
    print(f"Input: {result.get('input', 'N/A')}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Category: {result['category']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Explanations: {result['explanations']}")
    print(f"Mitigations: {result['mitigations']}")
    print("-" * 30)

if __name__ == "__main__":
    # 1. Trusted URL with sensitive path
    run_test("Trusted URL + Login", analyze_url("https://airtel.in/login"))
    # 2. Suspicious URL with IP
    run_test("Untrusted IP URL", analyze_url("http://192.168.1.1/verify-otp"))
    # 3. Legitimate SMS (Hi via)
    run_test("Legitimate SMS", analyze_message("Hey via, are we still on for lunch today?"))
    # 4. Scam SMS (OTP request)
    run_test("Scam SMS (OTP)", analyze_message("Urgent: Your account is suspended. Send OTP to 1234 to verify."))
    # 5. Promotional SMS (Ad)
    run_test("Promotional SMS", analyze_message("Get 50% off on your next purchase at local store. Visit us today!"))
    # 6. Trusted Email
    run_test("Trusted Link Email", analyze_email("Hello, please check your monthly statement at https://hdfcbank.com"))
