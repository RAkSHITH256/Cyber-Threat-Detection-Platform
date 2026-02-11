import sys, os
sys.path.append(os.getcwd())
from detectors.message_detector import analyze_message

def test_spam():
    result = analyze_message('Congratulations! You are a winner, claim your prize now')
    assert result['verdict'] == 'HIGH RISK (Scam SMS)', f"Expected HIGH RISK, got {result['verdict']}"
    print('Spam test passed')

def test_ham():
    result = analyze_message('Hey, are we still meeting at 5pm?')
    assert result['verdict'] == 'LOW RISK (Likely Safe)', f"Expected LOW RISK, got {result['verdict']}"
    print('Ham test passed')

if __name__ == '__main__':
    test_spam()
    test_ham()
