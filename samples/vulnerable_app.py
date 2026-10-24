"""Intentionally vulnerable sample — FOR DEMO ONLY. Never run in production.

Upload this file in RepoGuard AI to see the scanner light up.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)
API_KEY = "sk-proj-abc123def456ghi789"  # planted: hardcoded secret
DB_PASSWORD = "SuperSecret123!"


def get_user(user_id):
    conn = sqlite3.connect("app.db")
    # planted: SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return conn.execute(query).fetchone()


def run_ping(host):
    # planted: command injection
    os.system("ping -c 1 " + host)


def load_state(filename):
    # planted: unsafe deserialization
    with open(filename, "rb") as fh:
        return pickle.load(fh)


def hash_password(password):
    # planted: weak hashing
    return hashlib.md5(password.encode()).hexdigest()


def make_session_token():
    # planted: predictable randomness
    return str(random.randint(100000, 999999))


@app.route("/transfer")
def transfer():
    amount = request.args.get("amount")
    # planted: debug + TLS verification off
    requests.post("https://internal/api", data={"amt": amount}, verify=False)
    return "ok"


if __name__ == "__main__":
    app.run(debug=True)  # planted: debug mode
