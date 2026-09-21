"""Same app, hardened."""
import os
import sqlite3
import secrets
import ast as _ast
from flask import Flask, request, abort
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["APP_SECRET"]
DB = sqlite3.connect(":memory:", check_same_thread=False)


@app.route("/login")
def login():
    user = request.args.get("user", "")
    pw = request.args.get("pw", "")
    cursor = DB.cursor()
    cursor.execute("SELECT pw_hash FROM users WHERE name = ?", (user,))
    row = cursor.fetchone()
    if not row or not secrets.compare_digest(row[0], generate_password_hash(pw)):
        abort(401)
    return {"ok": True}


@app.route("/calc")
def calc():
    expr = request.args.get("e", "")
    node = _ast.parse(expr, mode="eval")
    if not all(isinstance(n, (_ast.Expression, _ast.BinOp, _ast.Constant,
                              _ast.Add, _ast.Sub, _ast.Mult, _ast.Div))
               for n in _ast.walk(node)):
        abort(400)
    return {"result": eval(compile(node, "<safe>", "eval"),
                           {"__builtins__": {}}, {})}