from flask import Flask, Response
import os
import requests

app = Flask(__name__)

# Get the GET_URL from environment variable
GET_URL = os.getenv("GET_URL")
# Get the HTTP_PROXY from environment variable
HTTP_PROXY = os.getenv("HTTP_PROXY")

# Prepare the proxies dictionary if HTTP_PROXY is set
proxies = {"http": HTTP_PROXY} if HTTP_PROXY else None

@app.route("/")
def index():
    if not GET_URL:
        return "GET_URL environment variable is not set", 500

    try:
        # Perform GET request to GET_URL using proxy if provided
        resp = requests.get(GET_URL, proxies=proxies)
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