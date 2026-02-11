import os
import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# 1. Sample Data (Embedded for simplicity, can be replaced with loading a CSV)
# "ham" = legitimate, "spam" = malicious
data = [
    # SPAM / PHISHING SAMPLES
    ("URGENT: Your account has been suspended. Click here to verify: http://bit.ly/fake", "spam"),
    ("Congratulations! You won a $1000 Walmart gift card. Call now 555-0199", "spam"),
    ("Congratulations! You are a winner, claim your prize now", "spam"),
    ("Your package delivery failed. Schedule redelivery here: http://track-pkg.com", "spam"),
    ("IRS Alert: You have unpaid taxes. A warrant has been issued.", "spam"),
    ("Verify your identity securely. Log in at http://secure-bank-login.com", "spam"),
    ("Hot singles in your area! Click to chat now.", "spam"),
    ("You have 1 voicemail. Click to listen.", "spam"),
    ("Free bitcoin! Claim your bonus now.", "spam"),
    ("Your computer is infected. Call Microsoft Support immediately.", "spam"),
    ("Loan approved! Get your cash now.", "spam"),
    ("Act now! Limited time offer.", "spam"),
    ("Cheap meds! No prescription needed.", "spam"),
    ("Make money fast working from home.", "spam"),
    ("Your subscription has expired. Renew now.", "spam"),
    
    # HAM / REAL SAMPLES
    ("Hey via, are we still on for lunch today?", "ham"),
    ("Don't forget to submit the report by 5 PM.", "ham"),
    ("Can you pick up some milk on your way home?", "ham"),
    ("Happy Birthday! Hope you have a great day.", "ham"),
    ("The meeting code is 123-456.", "ham"),
    ("I'll be there in 10 minutes.", "ham"),
    ("Thanks for your help yesterday.", "ham"),
    ("Did you see the game last night?", "ham"),
    ("Please review the attached document.", "ham"),
    ("Your appointment is confirmed for Tuesday at 2 PM.", "ham"),
    ("Let's reschedule our call.", "ham"),
    ("Where are you?", "ham"),
    ("Call me when you get a chance.", "ham"),
    ("I love this song!", "ham"),
]

messages, labels = zip(*data)

# 2. Create the Pipeline
# We use CountVectorizer to convert text to numbers, and MultinomialNB for classification
model = make_pipeline(CountVectorizer(), MultinomialNB())

# 3. Train the Model
print("Training model...")
model.fit(messages, labels)
print("Model trained.")

# 4. Save the Model
os.makedirs("models", exist_ok=True)
model_path = os.path.join("models", "spam_model.pkl")
joblib.dump(model, model_path)
print(f"Model saved to {model_path}")

# 5. Quick Test
test_msgs = [
    "Urgent! Verify your account now",
    "Hey, what's up?",
    "Free money just for you"
]
print("\nQuick Test Results:")
for msg in test_msgs:
    prediction = model.predict([msg])[0]
    proba = model.predict_proba([msg])[0]
    print(f"'{msg}' -> {prediction} (Spam probability: {proba[1]:.2f})")
