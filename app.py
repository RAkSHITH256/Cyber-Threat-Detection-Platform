from flask import Flask, render_template, request, jsonify
from detectors.url_detector import analyze_url
from detectors.number_detector import analyze_number
from detectors.message_detector import analyze_message
from detectors.email_detector import analyze_email

app = Flask(__name__)
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    result = None
    input_type = request.args.get("type", "url") # Default from query param if GET

    if request.method == "POST":
        # Handle both JSON and Form data
        if request.is_json:
            data = request.get_json()
            input_type = data.get("input_type")
            user_input = data.get("user_input")
        else:
            input_type = request.form.get("input_type")
            user_input = request.form.get("user_input")

        detector_map = {
            "url": (analyze_url, "URL"),
            "number": (analyze_number, "Phone Number"),
            "message": (analyze_message, "SMS / Message"),
            "email": (analyze_email, "Email Content")
        }

        if input_type in detector_map:
            analyze_fn, display_name = detector_map[input_type]
            analysis = analyze_fn(user_input)
            
            result = {
                "input_type": display_name,
                "input": user_input,
                "risk_score": analysis["risk_score"],
                "category": analysis["category"],
                "verdict": analysis["verdict"],
                "features": analysis["features"],
                "explanations": analysis.get("explanations", []),
                "mitigations": analysis.get("mitigations", [])
            }

        # Return JSON for AJAX requests
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(result)

    return render_template("index.html", result=result, default_type=input_type)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)



