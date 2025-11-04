from flask import Flask
import os

app = Flask(__name__)

# Get the message from environment variable
MESSAGE = os.getenv("APP_MESSAGE", "Hello from Docker!")

@app.route("/")
def index():
    return MESSAGE

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)