from flask import Flask, Response
import os
import requests

app = Flask(__name__)

# Get the GET_URL from environment variable
GET_URL = os.getenv("GET_URL")
EGRESS_UMA_URL = os.getenv("EGRESS_UMA_URL", "").rstrip("/")


def fetch(url):
    if not EGRESS_UMA_URL:
        return requests.get(url)
    return requests.post(
        f"{EGRESS_UMA_URL}/fetch",
        json={"url": url, "method": "GET", "headers": {}, "body": ""},
    )

@app.route("/")
def index():
    if not GET_URL:
        return "GET_URL environment variable is not set", 500

    try:
        resp = fetch(GET_URL)
        # Return the response content and status code
        return Response(
            resp.content,
            status=resp.status_code,
            content_type=resp.headers.get("Content-Type", "text/plain")
        )
    except requests.RequestException as e:
        return f"Error fetching {GET_URL}: {str(e)}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
