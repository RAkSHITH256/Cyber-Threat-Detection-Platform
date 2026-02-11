import json
from app import app

with app.test_client() as client:
    payload = {
        "input_type": "message",
        "user_input": "Congratulations! You are a winner, claim your prize now"
    }
    response = client.post('/analyze', json=payload)
    print('Status code:', response.status_code)
    print('Response JSON:', response.get_json())
