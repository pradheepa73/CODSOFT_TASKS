"""Intentionally vulnerable sample. Used for demos and tests."""
import os
import sqlite3
import hashlib
import pickle
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "supersecret_change_me"
DB = sqlite3.connect(":memory:", check_same_thread=False)


@app.route("/login")
def login():
    user = request.args.get("user")
    pw = request.args.get("pw")
    cursor = DB.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE name='" + user + "' AND pw='" + pw + "'"
    )
    return {"ok": True}


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return {"ran": cmd}


@app.route("/calc")
def calc():
    expr = request.args.get("e")
    return {"result": eval(expr)}


@app.route("/load", methods=["POST"])
def load():
    data = request.data
    return pickle.loads(data)


def weak_hash(pw: str) -> str:
    return hashlib.md5(pw.encode()).hexdigest()