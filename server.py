from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import time
import uuid

app = Flask(__name__)
app.secret_key = "patchone-dev-secret-key-change-me"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
GROUPS_FILE = os.path.join(DATA_DIR, "groups.json")
MESSAGES_FILE = os.path.join(DATA_DIR, "messages.json")

MAX_GROUP_SIZE = 10


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def ensure_data_files():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)
    if not os.path.exists(GROUPS_FILE):
        with open(GROUPS_FILE, "w") as f:
            json.dump({}, f)
    if not os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, "w") as f:
            json.dump([], f)


def load_json(path):
    with open(path, "r") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_users():
    return load_json(USERS_FILE)


def save_users(users):
    save_json(USERS_FILE, users)


def load_groups():
    return load_json(GROUPS_FILE)


def save_groups(groups):
    save_json(GROUPS_FILE, groups)


def load_messages():
    return load_json(MESSAGES_FILE)


def save_messages(messages):
    save_json(MESSAGES_FILE, messages)


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
def api_register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password are required."}), 400

    if len(username) < 3:
        return jsonify({"ok": False, "error": "Username must be at least 3 characters."}), 400

    if len(password) < 4:
        return jsonify({"ok": False, "error": "Password must be at least 4 characters."}), 400

    users = load_users()

    for existing in users.keys():
        if existing.lower() == username.lower():
            return jsonify({"ok": False, "error": "That username is already taken."}), 409

    users[username] = {
        "password_hash": generate_password_hash(password),
        "created_at": time.time(),
    }
    save_users(users)

    return jsonify({"ok": True, "message": "Account created. You can now log in."})


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    users = load_users()

    matched_username = None
    for existing in users.keys():
        if existing.lower() == username.lower():
            matched_username = existing
            break

    if not matched_username or not check_password_hash(users[matched_username]["password_hash"], password):
        return jsonify({"ok": False, "error": "Invalid username or password."}), 401

    session["username"] = matched_username
    return jsonify({"ok": True, "username": matched_username})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.pop("username", None)
    return jsonify({"ok": True})


@app.route("/api/me", methods=["GET"])
def api_me():
    username = session.get("username")
    if not username:
        return jsonify({"ok": False, "logged_in": False})
    return jsonify({"ok": True, "logged_in": True, "username": username})


def require_login():
    return session.get("username")


# ---------------------------------------------------------------------------
# Global chat API
# ---------------------------------------------------------------------------

@app.route("/api/messages", methods=["GET"])
def api_get_messages():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    messages = load_messages()
    return jsonify({"ok": True, "messages": messages[-200:]})


@app.route("/api/messages", methods=["POST"])
def api_post_message():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"ok": False, "error": "Message cannot be empty."}), 400

    if len(text) > 500:
        text = text[:500]

    messages = load_messages()
    messages.append({
        "username": username,
        "text": text,
        "timestamp": time.time(),
    })
    save_messages(messages)

    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Groups API
# ---------------------------------------------------------------------------

@app.route("/api/groups", methods=["GET"])
def api_get_groups():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    groups = load_groups()
    group_list = []
    for group_id, group in groups.items():
        group_list.append({
            "id": group_id,
            "name": group["name"],
            "owner": group["owner"],
            "members": group["members"],
            "member_count": len(group["members"]),
            "max_members": MAX_GROUP_SIZE,
        })

    group_list.sort(key=lambda g: g.get("member_count", 0), reverse=True)

    return jsonify({"ok": True, "groups": group_list})


@app.route("/api/groups/create", methods=["POST"])
def api_create_group():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()

    if not name:
        return jsonify({"ok": False, "error": "Group name is required."}), 400

    if len(name) > 50:
        name = name[:50]

    groups = load_groups()

    group_id = uuid.uuid4().hex[:8]
    groups[group_id] = {
        "name": name,
        "owner": username,
        "members": [username],
        "created_at": time.time(),
    }
    save_groups(groups)

    return jsonify({"ok": True, "group_id": group_id})


@app.route("/api/groups/join", methods=["POST"])
def api_join_group():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()

    groups = load_groups()

    if group_id not in groups:
        return jsonify({"ok": False, "error": "Group not found."}), 404

    group = groups[group_id]

    if username in group["members"]:
        return jsonify({"ok": False, "error": "You are already in this group."}), 400

    if len(group["members"]) >= MAX_GROUP_SIZE:
        return jsonify({"ok": False, "error": "This group is full (max 10 players)."}), 400

    group["members"].append(username)
    save_groups(groups)

    return jsonify({"ok": True, "message": "Joined group '{}'.".format(group["name"])})


@app.route("/api/groups/leave", methods=["POST"])
def api_leave_group():
    username = require_login()
    if not username:
        return jsonify({"ok": False, "error": "Not logged in."}), 401

    data = request.get_json(silent=True) or {}
    group_id = (data.get("group_id") or "").strip()

    groups = load_groups()

    if group_id not in groups:
        return jsonify({"ok": False, "error": "Group not found."}), 404

    group = groups[group_id]

    if username not in group["members"]:
        return jsonify({"ok": False, "error": "You are not in this group."}), 400

    group["members"].remove(username)

    if len(group["members"]) == 0:
        del groups[group_id]
    else:
        if group["owner"] == username:
            group["owner"] = group["members"][0]

    save_groups(groups)

    return jsonify({"ok": True})


if __name__ == "__main__":
    ensure_data_files()
    app.run(debug=True, host="0.0.0.0", port=5000)