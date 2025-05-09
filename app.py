import os
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB limit

@app.route("/webhook", methods=["POST"])
def webhook():
    print("Received request at /webhook")
    print("Headers:", dict(request.headers))
    print("Body:", request.data.decode())
    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(port=port, host="0.0.0.0")