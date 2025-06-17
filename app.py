# github-activity-hook/app.py
from flask import Flask, request, jsonify
import os, hmac, hashlib, requests
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

app = Flask(__name__)

# Use consistent naming and ensure variables are present
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
USERNAME = os.getenv("USERNAME")
TRACKER_REPO = os.getenv("TRACKER_REPO")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

# Basic sanity checks for required environment variables
if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN environment variable not set. Dispatch will fail.")
if not USERNAME:
    print("Error: USERNAME environment variable not set. Dispatch target is unknown.")
if not TRACKER_REPO:
    print("Error: TRACKER_REPO environment variable not set. Dispatch target is unknown.")
if not WEBHOOK_SECRET:
    print("Warning: WEBHOOK_SECRET environment variable not set. Webhook signature verification will be skipped.")


@app.route('/')
def home():
    return "GitHub Activity Tracker webhook service is up and running!"

def verify_signature(data, sig_header):
    if not WEBHOOK_SECRET:
        print("WEBHOOK_SECRET not set, skipping signature verification.")
        return True # Or False if you want to enforce it always

    mac = hmac.new(WEBHOOK_SECRET.encode(), msg=data, digestmod=hashlib.sha256)
    expected_signature = f"sha256={mac.hexdigest()}"
    return hmac.compare_digest(expected_signature, sig_header)

@app.route("/webhook", methods=["POST"])
def webhook():
    # Verify signature if WEBHOOK_SECRET is set
    if WEBHOOK_SECRET:
        signature = request.headers.get("X-Hub-Signature-256")
        if not signature:
            print("Webhook received without X-Hub-Signature-256 header.")
            return jsonify({"error": "Missing signature header"}), 401
        if not verify_signature(request.data, signature):
            print("Invalid signature received.")
            return jsonify({"error": "Invalid signature"}), 401
    else:
        print("WEBHOOK_SECRET is not set. Skipping signature verification (NOT RECOMMENDED FOR PRODUCTION).")

    # You could filter by event type here if needed
    # For example:
    # event_type = request.headers.get("X-GitHub-Event")
    # if event_type not in ["push", "pull_request", "issues", "issue_comment"]:
    #     print(f"Ignoring event type: {event_type}")
    #     return jsonify({"message": f"Ignored event type: {event_type}"}), 200

    print("✅ Webhook received. Dispatching 'update-tracker' event...")

    # Ensure all required dispatch variables are available
    if not (USERNAME and TRACKER_REPO and GITHUB_TOKEN):
        return jsonify({"error": "Missing environment variables for dispatch."}), 500

    dispatch_url = f"https://api.github.com/repos/{USERNAME}/{TRACKER_REPO}/dispatches"
    dispatch_headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    dispatch_json = {"event_type": "update-tracker"}

    try:
        r = requests.post(
            dispatch_url,
            headers=dispatch_headers,
            json=dispatch_json
        )
        r.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)

        if r.status_code == 204: # 204 No Content is common for successful dispatches
            print(f"✅ Dispatch successful to {USERNAME}/{TRACKER_REPO}")
            return jsonify({"message": "Repository dispatch successful!"}), 200
        else:
            # Should not reach here if raise_for_status() works, but for safety
            print(f"❌ Dispatch failed with status {r.status_code}: {r.text}")
            return jsonify({"error": "Dispatch failed", "detail": r.text}), 500
    except requests.exceptions.RequestException as e:
        print(f"❌ Error during repository dispatch: {e}")
        return jsonify({"error": "Error dispatching event", "detail": str(e)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)