
"""LandTrust backend: Flask + SQLite. Run: python server.py"""

import sqlite3
import json
import hashlib
import secrets
import time
import os

from flask import Flask, request, jsonify, g, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash

DB = os.environ.get("LT_DB", "landtrust.db")

app = Flask(__name__, static_folder="static", static_url_path="")

TOKENS = {}


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d:
        d.close()


def h(prev, text):
    return hashlib.sha256((prev + text).encode()).hexdigest()[:16]


def log(pid, event, actor):
    d = db()

    last = d.execute(
        "SELECT hash FROM history WHERE parcel_id=? ORDER BY id DESC LIMIT 1",
        (pid,)
    ).fetchone()

    prev = last["hash"] if last else "0" * 16
    ts = int(time.time())

    d.execute(
        "INSERT INTO history(parcel_id,event,actor,ts,prev,hash) VALUES(?,?,?,?,?,?)",
        (pid, event, actor, ts, prev, h(prev, f"{event}|{actor}|{ts}"))
    )


def init():
    d = sqlite3.connect(DB)
    d.row_factory = sqlite3.Row

    d.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT
    );

    CREATE TABLE IF NOT EXISTS parcels(
        id TEXT PRIMARY KEY,
        village TEXT,
        owner TEXT,
        area REAL,
        class TEXT,
        geom TEXT,
        status TEXT,
        khata TEXT
    );

    CREATE TABLE IF NOT EXISTS registrations(
        id INTEGER PRIMARY KEY,
        parcel_id TEXT,
        seller TEXT,
        buyer TEXT,
        date TEXT
    );

    CREATE TABLE IF NOT EXISTS mutations(
        id INTEGER PRIMARY KEY,
        parcel_id TEXT,
        new_owner TEXT,
        reg_id INTEGER,
        status TEXT
    );

    CREATE TABLE IF NOT EXISTS history(
        id INTEGER PRIMARY KEY,
        parcel_id TEXT,
        event TEXT,
        actor TEXT,
        ts INTEGER,
        prev TEXT,
        hash TEXT
    );
    """)

    # Migrate existing plain-text passwords to password hashes.
    users = d.execute(
        "SELECT username, password FROM users"
    ).fetchall()

    for existing_user in users:
        old_password = existing_user["password"] or ""

        if not old_password.startswith(("scrypt:", "pbkdf2:")):
            hashed_password = generate_password_hash(old_password)

            d.execute(
                "UPDATE users SET password=? WHERE username=?",
                (hashed_password, existing_user["username"])
            )

    # Create demo accounts if no users exist.
    if not d.execute("SELECT 1 FROM users").fetchone():

        d.executemany(
            "INSERT INTO users VALUES(?,?,?)",
            [
                (
                    "surveyor",
                    generate_password_hash("survey123"),
                    "surveyor"
                ),
                (
                    "officer",
                    generate_password_hash("officer123"),
                    "officer"
                )
            ]
        )

        b = (80.2000, 13.0000)
        s = 0.001

        cells = [
            (0, 0, 1, 1),
            (1, 0, 2, 1),
            (2, 0, 3, 1),
            (0, 1, 1, 2),
            (1, 1, 2, 2),
            (2, 1, 3, 2),
            (0, 2, 3, 3)
        ]

        names = [
            "A. Murugan",
            "K. Selvi",
            "R. Prakash",
            "S. Lakshmi",
            "M. Ravi",
            "P. Anand",
            "V. Kumar"
        ]

        cls = [
            "Irrigated",
            "Irrigated",
            "Dry",
            "Dry",
            "Irrigated",
            "Orchard",
            "Irrigated"
        ]

        for i, (x0, y0, x1, y1) in enumerate(cells):

            poly = [
                [b[0] + x0 * s, b[1] + y0 * s],
                [b[0] + x1 * s, b[1] + y0 * s],
                [b[0] + x1 * s, b[1] + y1 * s],
                [b[0] + x0 * s, b[1] + y1 * s]
            ]

            area = round((x1 - x0) * (y1 - y0) * 1.1, 2)

            d.execute(
                "INSERT INTO parcels VALUES(?,?,?,?,?,?,?,?)",
                (
                    f"P{i+1}",
                    "Sample Village",
                    names[i],
                    area,
                    cls[i],
                    json.dumps(poly),
                    "Awaiting verification" if i in (2, 4) else "Verified",
                    f"K-{100+i}"
                )
            )

        d.commit()

        with app.app_context():
            g.db = d

            for i in range(7):
                log(f"P{i+1}", "Original chain-survey entry", "system")
                log(f"P{i+1}", "Resurveyed with drone and RTK", "system")

            d.commit()
            g.pop("db")

    d.commit()
    d.close()


def user(role=None):
    u = TOKENS.get(
        request.headers.get("Authorization", "").replace("Bearer ", "")
    )

    if not u or (role and u["role"] != role):
        abort(401 if not u else 403)

    return u


@app.post("/api/login")
def login():
    j = request.json or {}

    username = j.get("username")
    password = j.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Wrong username or password"), 401

    r = db().execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    ).fetchone()

    if not r or not check_password_hash(r["password"], password):
        return jsonify(error="Wrong username or password"), 401

    t = secrets.token_hex(16)

    TOKENS[t] = {
        "username": r["username"],
        "role": r["role"]
    }

    return jsonify(
        token=t,
        role=r["role"],
        username=r["username"]
    )


@app.get("/api/parcels")
def parcels():
    q = request.args.get("q", "").lower()

    rows = db().execute("SELECT * FROM parcels").fetchall()

    return jsonify([
        {**dict(r), "geom": json.loads(r["geom"])}
        for r in rows
        if q in (r["id"] + r["owner"] + r["khata"]).lower()
    ])


def chain_ok(pid):
    prev = "0" * 16

    for r in db().execute(
        "SELECT * FROM history WHERE parcel_id=? ORDER BY id",
        (pid,)
    ):
        if (
            r["prev"] != prev
            or r["hash"] != h(
                prev,
                f"{r['event']}|{r['actor']}|{r['ts']}"
            )
        ):
            return False

        prev = r["hash"]

    return True


@app.get("/api/parcels/<pid>")
def parcel(pid):
    d = db()

    p = d.execute(
        "SELECT * FROM parcels WHERE id=?",
        (pid,)
    ).fetchone() or abort(404)

    q = lambda t: [
        dict(r)
        for r in d.execute(
            f"SELECT * FROM {t} WHERE parcel_id=? ORDER BY id DESC",
            (pid,)
        )
    ]

    return jsonify(
        parcel={**dict(p), "geom": json.loads(p["geom"])},
        registrations=q("registrations"),
        mutations=q("mutations"),
        history=[
            dict(r)
            for r in d.execute(
                "SELECT * FROM history WHERE parcel_id=? ORDER BY id",
                (pid,)
            )
        ],
        chain_valid=chain_ok(pid)
    )


@app.post("/api/parcels/<pid>/verify")
def verify(pid):
    u = user("surveyor")
    d = db()

    d.execute(
        "UPDATE parcels SET status='Verified' WHERE id=?",
        (pid,)
    )

    log(pid, "Owner confirmed boundary on mobile app", u["username"])

    d.commit()

    return jsonify(ok=True)


@app.post("/api/parcels/<pid>/dispute")
def dispute(pid):
    u = user()
    d = db()

    note = (request.json or {}).get("note", "No details")[:200]

    d.execute(
        "UPDATE parcels SET status='Dispute flagged' WHERE id=?",
        (pid,)
    )

    log(pid, "Dispute flagged: " + note, u["username"])

    d.commit()

    return jsonify(ok=True)


@app.post("/api/registrations")
def register():
    u = user("officer")
    j = request.json or {}
    d = db()

    pid = j.get("parcel_id")

    p = d.execute(
        "SELECT * FROM parcels WHERE id=?",
        (pid,)
    ).fetchone() or abort(404)

    buyer = (j.get("buyer") or "").strip()

    if not buyer:
        return jsonify(error="Buyer name is required"), 400

    if p["status"] == "Dispute flagged":
        return jsonify(error="Parcel has an open dispute"), 409

    c = d.execute(
        "INSERT INTO registrations(parcel_id,seller,buyer,date) VALUES(?,?,?,date('now'))",
        (pid, p["owner"], buyer)
    )

    d.execute(
        "INSERT INTO mutations(parcel_id,new_owner,reg_id,status) VALUES(?,?,?,'Pending')",
        (pid, buyer, c.lastrowid)
    )

    log(
        pid,
        f"Sale registered: {p['owner']} to {buyer}. Mutation case opened automatically",
        u["username"]
    )

    d.commit()

    return jsonify(ok=True)


@app.post("/api/mutations/<int:mid>/approve")
def approve(mid):
    u = user("officer")
    d = db()

    m = d.execute(
        "SELECT * FROM mutations WHERE id=? AND status='Pending'",
        (mid,)
    ).fetchone() or abort(404)

    d.execute(
        "UPDATE mutations SET status='Approved' WHERE id=?",
        (mid,)
    )

    d.execute(
        "UPDATE parcels SET owner=? WHERE id=?",
        (m["new_owner"], m["parcel_id"])
    )

    log(
        m["parcel_id"],
        f"Mutation approved. New owner: {m['new_owner']}",
        u["username"]
    )

    d.commit()

    return jsonify(ok=True)


@app.get("/api/stats")
def stats():
    d = db()

    c = lambda sql: d.execute(sql).fetchone()[0]

    return jsonify(
        parcels=c("SELECT COUNT(*) FROM parcels"),
        verified=c("SELECT COUNT(*) FROM parcels WHERE status='Verified'"),
        pending_mutations=c("SELECT COUNT(*) FROM mutations WHERE status='Pending'"),
        disputes=c("SELECT COUNT(*) FROM parcels WHERE status='Dispute flagged'")
    )


@app.errorhandler(401)
def e401(_):
    return jsonify(error="Please sign in"), 401


@app.errorhandler(403)
def e403(_):
    return jsonify(error="Your role can't do this"), 403


@app.errorhandler(404)
def e404(_):
    return jsonify(error="Not found"), 404


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


init()


if __name__ == "__main__":
    app.run(
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
