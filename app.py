from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from engine import full_check, load_dictionary

app = Flask(__name__)
CORS(app)  # allows the browser extension (running on other websites) to call this server

print("Loading RockYou dictionary... (only happens once, when the server starts)")
dictionary_hashes = load_dictionary()
print(f"Loaded {len(dictionary_hashes):,} passwords. Server ready.")


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password:
            result = full_check(password, dictionary_hashes)
    return render_template("index.html", result=result)


@app.route("/api/check", methods=["POST"])
def api_check():
    """
    A data-only version of the check, for the browser extension to use.
    Instead of returning a full webpage, it just returns the result as
    plain data (JSON) that the extension can read and display.
    """
    data = request.get_json()
    password = data.get("password", "") if data else ""
    if not password:
        return jsonify({"error": "no password provided"}), 400
    result = full_check(password, dictionary_hashes)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)