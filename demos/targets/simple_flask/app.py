from flask import Flask, request, render_template_string
import sqlite3

import jwt
from datetime import datetime, timedelta, timezone
app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>UMANI demo target</h1>
    <ul>
        <li><a href="/about">About</a></li>
        <li><a href="/contact">Contact</a></li>
        <li><a href="/search?q=hi">Search</a></li>
    </ul>
    """

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # deliberately vulnerable: reflected XSS
    return render_template_string(f"<p>Results for: {q}</p>")


@app.route("/user")
def user():
    uid = request.args.get("id", "1")
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE u (id INTEGER, name TEXT)")
    conn.execute("INSERT INTO u VALUES (1, 'alice')")
    # deliberately vulnerable: string-concatenated SQL
    cur = conn.execute(f"SELECT name FROM u WHERE id = {uid}")
    return str(cur.fetchall())
from flask import make_response


@app.route("/api/cors")
def cors_vuln():
    resp = make_response('{"user": "alice", "role": "admin"}')
    origin = request.headers.get("Origin", "")
    # deliberately vulnerable: reflect any Origin with credentials
    resp.headers["Access-Control-Allow-Origin"] = origin
    resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

from flask import redirect as flask_redirect


@app.route("/redirect")
def redirect_vuln():
    # deliberately vulnerable: redirects to any user-supplied URL
    target = request.args.get("url", "/")
    return flask_redirect(target)

@app.route("/admin")
def admin_hidden():
    return "admin panel"


@app.route("/backup")
def backup_hidden():
    return "backup files"

@app.route("/about")
def about():
    return """
    <h1>About</h1>
    <a href="/contact">Contact</a>
    <a href="/search?q=test">Search</a>
    """


@app.route("/contact")
def contact():
    return """
    <h1>Contact</h1>
    <form action="/submit" method="POST">
        <input name="name">
        <input name="message">
        <button>Send</button>
    </form>
    """


@app.route("/submit", methods=["POST"])
def submit():
    return "received"

JWT_SECRET = "secret"   # deliberately weak

@app.route("/api/me")
def api_me():
    # deliberately weak: HS256 with a guessable secret
    payload = {
        "sub": "alice",
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return {"token": token}
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
