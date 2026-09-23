import re
import urllib.request

import urllib.request

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

@app.route("/profile")
def profile():
    # CSRF-vulnerable: no token
    return """
    <h1>Update Profile</h1>
    <form action="/profile/update" method="POST">
        <input name="email" value="alice@example.com">
        <input name="bio" value="hello">
        <button>Save</button>
    </form>
    """


@app.route("/password")
def password():
    # CSRF-protected: includes a token
    return """
    <h1>Change Password</h1>
    <form action="/password/change" method="POST">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="password" name="new_password">
        <button>Change</button>
    </form>
    """


@app.route("/profile/update", methods=["POST"])
def profile_update():
    return "updated"


@app.route("/password/change", methods=["POST"])
def password_change():
    return "changed"

@app.route("/lookup")
def lookup():
    # returns different content based on user input — perfect for fuzzing
    name = request.args.get("name", "")
    if name == "admin":
        return "user found: admin (role=administrator)"
    elif name:
        return f"no user: {name}"
    return "no user specified"


@app.route("/fetch")
def fetch():
    # deliberately vulnerable: fetches any user-supplied URL server-side
    target_url = request.args.get("url", "")
    if not target_url:
        return "no url"
    try:
        with urllib.request.urlopen(target_url, timeout=3) as r:
            return r.read(500).decode("utf-8", errors="ignore")
    except Exception as e:
        return f"error: {e}"


@app.route("/api/xml", methods=["POST"])
def xml_parse():
    # deliberately vulnerable: resolves external entities, including HTTP
    body = request.get_data().decode("utf-8", errors="ignore")

    # naive external entity resolution (the vulnerability)
    entity_pattern = re.compile(
        r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>')
    entities = dict(entity_pattern.findall(body))

    for name, uri in entities.items():
        try:
            if uri.startswith("file://"):
                with open(uri[7:], "r") as f:
                    value = f.read()
            elif uri.startswith("http://") or uri.startswith("https://"):
                with urllib.request.urlopen(uri, timeout=3) as r:
                    value = r.read(2048).decode("utf-8", errors="ignore")
            else:
                value = ""
        except Exception as e:
           value = f"error: {e}"
        body = body.replace(f"&{name};", value)

    # strip the DOCTYPE now that entities are resolved
    body = re.sub(r"<!DOCTYPE.*?\]>", "", body, flags=re.DOTALL)
    return body
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
