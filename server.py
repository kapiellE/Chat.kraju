import os
import sqlite3
from datetime import datetime

from flask import Flask, g, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "patchone.db")
SECRET_KEY_PATH = os.path.join(BASE_DIR, "secret.key")

app = Flask(__name__)


def get_secret_key():
    # Keep the session secret stable across restarts so logged-in users
    # aren't kicked out every time the server restarts.
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, "r") as f:
            return f.read().strip()
    key = os.urandom(32).hex()
    with open(SECRET_KEY_PATH, "w") as f:
        f.write(key)
    return key


app.secret_key = get_secret_key()


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def current_user_row():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def require_login():
    user = current_user_row()
    if not user:
        return None, (jsonify(error="Not logged in."), 401)
    return user, None


def is_member(db, group_id, user_id):
    row = db.execute(
        "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user_id),
    ).fetchone()
    return row is not None


def group_to_dict(db, group_row):
    members = db.execute(
        """
        SELECT users.username FROM group_members
        JOIN users ON users.id = group_members.user_id
        WHERE group_members.group_id = ?
        ORDER BY users.username COLLATE NOCASE
        """,
        (group_row["id"],),
    ).fetchall()
    owner = db.execute(
        "SELECT username FROM users WHERE id = ?", (group_row["owner_id"],)
    ).fetchone()
    return {
        "id": group_row["id"],
        "name": group_row["name"],
        "owner": owner["username"] if owner else None,
        "owner_id": group_row["owner_id"],
        "members": [m["username"] for m in members],
    }


# ---------------------------------------------------------------------------
# Page route
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Auth API
# ---------------------------------------------------------------------------

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(error="Enter a nickname and password."), 400
    if len(username) > 32:
        return jsonify(error="Nickname is too long."), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if existing:
        return jsonify(error="That nickname is already taken."), 409

    password_hash = generate_password_hash(password)
    db.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
        (username, password_hash, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify(message="Registered successfully. You can log in now.")


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify(error="Invalid nickname or password."), 401

    session["user_id"] = user["id"]
    return jsonify(username=user["username"])


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(message="Logged out.")


@app.route("/api/me")
def me():
    user = current_user_row()
    if not user:
        return jsonify(logged_in=False)
    return jsonify(logged_in=True, username=user["username"])


@app.route("/api/users")
def list_users():
    user, err = require_login()
    if err:
        return err
    db = get_db()
    rows = db.execute(
        "SELECT username FROM users WHERE id != ? ORDER BY username COLLATE NOCASE",
        (user["id"],),
    ).fetchall()
    return jsonify(users=[r["username"] for r in rows])


# ---------------------------------------------------------------------------
# Group API
# ---------------------------------------------------------------------------

@app.route("/api/groups", methods=["GET"])
def list_groups():
    user, err = require_login()
    if err:
        return err
    db = get_db()
    rows = db.execute(
        """
        SELECT groups.* FROM groups
        JOIN group_members ON group_members.group_id = groups.id
        WHERE group_members.user_id = ?
        ORDER BY groups.created_at
        """,
        (user["id"],),
    ).fetchall()
    return jsonify(groups=[group_to_dict(db, r) for r in rows])


@app.route("/api/groups", methods=["POST"])
def create_group():
    user, err = require_login()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    member_usernames = data.get("members") or []

    if not name:
        return jsonify(error="Enter a group name."), 400

    db = get_db()
    existing = db.execute("SELECT id FROM groups WHERE name = ?", (name,)).fetchone()
    if existing:
        return jsonify(error="That group already exists."), 409

    cur = db.execute(
        "INSERT INTO groups (name, owner_id, created_at) VALUES (?, ?, ?)",
        (name, user["id"], datetime.utcnow().isoformat()),
    )
    group_id = cur.lastrowid

    # Owner is always a member.
    db.execute(
        "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
        (group_id, user["id"]),
    )

    if member_usernames:
        placeholders = ",".join("?" for _ in member_usernames)
        rows = db.execute(
            f"SELECT id FROM users WHERE username IN ({placeholders})",
            member_usernames,
        ).fetchall()
        for r in rows:
            db.execute(
                "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
                (group_id, r["id"]),
            )

    db.commit()
    group_row = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    return jsonify(group=group_to_dict(db, group_row))


@app.route("/api/groups/<int:group_id>/join", methods=["POST"])
def join_group(group_id):
    user, err = require_login()
    if err:
        return err
    db = get_db()
    group_row = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group_row:
        return jsonify(error="That group does not exist."), 404
    db.execute(
        "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
        (group_id, user["id"]),
    )
    db.commit()
    return jsonify(group=group_to_dict(db, group_row))


@app.route("/api/groups/<int:group_id>/members", methods=["POST"])
def add_member(group_id):
    user, err = require_login()
    if err:
        return err
    db = get_db()
    group_row = db.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone()
    if not group_row:
        return jsonify(error="That group does not exist."), 404
    if group_row["owner_id"] != user["id"]:
        return jsonify(error="Only the group owner can add members."), 403

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify(error="Enter a nickname to add."), 400

    target = db.execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not target:
        return jsonify(error="No user with that nickname."), 404

    db.execute(
        "INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)",
        (group_id, target["id"]),
    )
    db.commit()
    return jsonify(group=group_to_dict(db, group_row))


# ---------------------------------------------------------------------------
# Chat API
# ---------------------------------------------------------------------------

@app.route("/api/groups/<int:group_id>/messages", methods=["GET"])
def get_messages(group_id):
    user, err = require_login()
    if err:
        return err
    db = get_db()
    if not is_member(db, group_id, user["id"]):
        return jsonify(error="You are not a member of this group."), 403

    rows = db.execute(
        """
        SELECT messages.text, messages.created_at, users.username
        FROM messages
        JOIN users ON users.id = messages.user_id
        WHERE messages.group_id = ?
        ORDER BY messages.id ASC
        """,
        (group_id,),
    ).fetchall()
    messages = [
        {
            "username": r["username"],
            "text": r["text"],
            "time": r["created_at"],
        }
        for r in rows
    ]
    return jsonify(messages=messages)


@app.route("/api/groups/<int:group_id>/messages", methods=["POST"])
def post_message(group_id):
    user, err = require_login()
    if err:
        return err
    db = get_db()
    if not is_member(db, group_id, user["id"]):
        return jsonify(error="You are not a member of this group."), 403

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()
    if not text:
        return jsonify(error="Message is empty."), 400

    created_at = datetime.utcnow().isoformat()
    db.execute(
        "INSERT INTO messages (group_id, user_id, text, created_at) VALUES (?, ?, ?, ?)",
        (group_id, user["id"], text, created_at),
    )
    db.commit()
    return jsonify(username=user["username"], text=text, time=created_at)


init_db()

if __name__ == "__main__":
    app.run(debug=True)
