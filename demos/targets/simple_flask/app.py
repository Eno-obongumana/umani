from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)


@app.route("/")
def home():
    return "<h1>UMANI demo target</h1><a href='/search?q=hi'>search</a>"


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


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
