from flask import Flask, request, jsonify
import os, hmac, hashlib, requests
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
USERNAME = os.getenv("USERNAME")
TRACKER_REPO = os.getenv("TRACKER_REPO")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

@app.route('/')
def home():
    return "GitHub Activity Tracker up and running!"

def verify_signature(data, sig):
    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=data, digestmod=hashlib.sha256)
    expected = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected, sig)

@app.route("/webhook", methods=["POST"])
def webhook():
    if WEBHOOK_SECRET:
        signature = request.headers.get("X-Hub-Signature-256")
        if not signature or not verify_signature(request.data, signature):
            return jsonify({"error": "Invalid signature"}), 401

    # You could filter by event type here if needed

    print("✅ Webhook received. Dispatching...")

    r = requests.post(
        f"https://api.github.com/repos/{USERNAME}/{TRACKER_REPO}/dispatches",
        headers={
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        },
        json={"event_type": "update-tracker"}
    )

    if r.status_code == 204:
        return jsonify({"message": "Dispatched!"}), 200
    else:
        return jsonify({"error": "Dispatch failed", "detail": r.text}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
