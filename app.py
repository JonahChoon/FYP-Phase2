"""
SC4012 CTF Tutor -- web app.
Student-facing site on the SAME shared core (ctf_core) as the CLI.
Phase 2: reads the 10 challenges directly from ctf_core (no challenge DB yet).

Sign-in is via OAuth (GitHub / Google / Microsoft) with a demo fallback -- see
auth.py. The AI tutor uses Gemini (GEMINI_API_KEY); hints and flag checking work
without it.

Run:  pip install -r requirements.txt  &&  python3 app.py   (http://localhost:5000)
"""

import os
import time
import uuid
from functools import wraps

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import ctf_core as core
import auth
import store

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24).hex())

FILES_DIR = os.path.join(os.path.dirname(__file__), "challenge_files")
os.makedirs(FILES_DIR, exist_ok=True)

MODE = core.MODE_GUIDED
MODEL_NAME = os.environ.get("GEMINI_MODEL", core.DEFAULT_MODEL)
_redactor = core.Redactor()

store.init_db()                    # creates tracker.db on first run
auth.init_auth(app)                # adds /login, /login/<provider>, /auth/<provider>, /logout


# ---------------------------------------------------------------------------
# Challenges (read straight from ctf_core for now)
# ---------------------------------------------------------------------------

def get_challenge(key):
    ch = core.CHALLENGES.get(key)
    if not ch:
        return None
    d = dict(ch)
    d["key"] = key
    d.setdefault("file_name", None)
    return d


def grouped_challenges():
    grouped = {}
    for key in core.CHALLENGES:
        ch = get_challenge(key)
        grouped.setdefault(ch["tutorial"], []).append(ch)
    return grouped


# ---------------------------------------------------------------------------
# Gemini tutor
# ---------------------------------------------------------------------------

class TutorModel:
    def __init__(self, model_name, temperature=core.DEFAULT_TEMPERATURE):
        self.model_name = model_name
        self.temperature = temperature
        self._client = None

    def _client_or_init(self):
        if self._client is None:
            key = os.environ.get("GEMINI_API_KEY")
            if not key:
                raise RuntimeError("GEMINI_API_KEY not set")
            from google import genai
            self._client = genai.Client(api_key=key)
        return self._client

    def build_chat(self, system_prompt, history):
        c = self._client_or_init()
        return c.chats.create(
            model=self.model_name, history=history or None,
            config={"system_instruction": system_prompt, "temperature": self.temperature})


MODEL = TutorModel(MODEL_NAME)
AI_CONFIGURED = bool(os.environ.get("GEMINI_API_KEY"))


# ---------------------------------------------------------------------------
# State + auth helpers
# ---------------------------------------------------------------------------

def current_user_id() -> str:
    """Stable id for the signed-in user, used as the key for saved progress."""
    u = session.get("user") or {}
    return (u.get("email") or f"{u.get('provider','?')}:{u.get('name','user')}").lower()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)
    return wrapper


@app.context_processor
def inject_user():
    return {"user": session.get("user")}


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    grouped = grouped_challenges()
    solved = store.solved_map(current_user_id())
    solved_count = sum(1 for v in solved.values() if v)
    total = len(core.CHALLENGES)
    labels = {6: "Tutorial 6 — Binary exploitation (Pwn)",
              7: "Tutorial 7 — Forensics & steganography"}
    return render_template("challenges.html", grouped=grouped, labels=labels,
                           solved=solved, solved_count=solved_count, total=total)


@app.route("/challenge/<key>")
@login_required
def challenge(key):
    ch = get_challenge(key)
    if not ch:
        abort(404)
    uid = current_user_id()
    prog = store.get_progress(uid, key)
    pub = ch["public"]
    max_hint = max(pub["hints"].keys()) if pub["hints"] else 0
    unlocked = [(lvl, pub["hints"][lvl]) for lvl in range(1, prog["hint_level"] + 1)]
    messages = store.get_messages(uid, key)   # persisted transcript
    return render_template("challenge.html", key=key, ch=ch, pub=pub,
                           unlocked=unlocked, hint_level=prog["hint_level"],
                           max_hint=max_hint, solved=prog["solved"],
                           messages=messages, ai_configured=AI_CONFIGURED)


@app.route("/challenge/<key>/hint", methods=["POST"])
@login_required
def unlock_hint(key):
    ch = get_challenge(key)
    if not ch:
        abort(404)
    uid = current_user_id()
    prog = store.get_progress(uid, key)
    max_hint = max(ch["public"]["hints"].keys()) if ch["public"]["hints"] else 0
    if prog["hint_level"] < max_hint:
        new_level = prog["hint_level"] + 1
        store.set_hint_level(uid, key, new_level)
        store.log_event(event="hint_unlock", user=uid, challenge=key,
                        prompt_version=core.PROMPT_VERSION, mode=MODE, model=MODEL_NAME,
                        hint_level=new_level, conversation_id=prog["conversation_id"])
        flash(f"Hint {new_level} unlocked.", "ok")
    else:
        flash("All hints are already unlocked.", "ok")
    return redirect(url_for("challenge", key=key))


@app.route("/challenge/<key>/flag", methods=["POST"])
@login_required
def submit_flag(key):
    ch = get_challenge(key)
    if not ch:
        abort(404)
    uid = current_user_id()
    prog = store.get_progress(uid, key)
    correct = core.check_flag(ch, request.form.get("flag", ""))
    if correct:
        store.set_solved(uid, key)
        flash("Correct flag — challenge solved.", "ok")
    else:
        flash("That flag isn't right. Keep going.", "err")
    # Log the attempt WITHOUT the flag value (Decision 4: flags are never stored).
    store.log_event(event="flag_submit", user=uid, challenge=key,
                    prompt_version=core.PROMPT_VERSION, mode=MODE, model=MODEL_NAME,
                    hint_level=prog["hint_level"], conversation_id=prog["conversation_id"],
                    reply="correct" if correct else "incorrect")
    return redirect(url_for("challenge", key=key))


@app.route("/challenge/<key>/chat", methods=["POST"])
@login_required
def chat(key):
    ch = get_challenge(key)
    if not ch:
        abort(404)
    uid = current_user_id()
    prog = store.get_progress(uid, key)
    msg = (request.json or {}).get("message", "").strip()
    if not msg:
        return jsonify(reply="", kind="sys")

    if core.is_exact_flag(ch, msg):
        return jsonify(reply="That looks like the flag — submit it in the flag "
                             "box above, not the chat.", kind="sys")

    safe = _redactor.redact(msg)
    # Build the chat fresh from the stored transcript, so it survives restarts.
    try:
        sys_prompt = core.build_system_prompt(ch, prog["hint_level"], MODE)
        chat_obj = MODEL.build_chat(sys_prompt, store.genai_history(uid, key))
    except RuntimeError:
        return jsonify(reply="The AI tutor isn't set up yet (no GEMINI_API_KEY). "
                             "Hints and flag checking still work.", kind="sys")

    # Send with a few retries on transient 503 overloads.
    reply, last_err, t0 = None, None, time.time()
    for attempt in range(3):
        try:
            resp = chat_obj.send_message(safe)
            reply = _redactor.redact(resp.text or "")
            break
        except Exception as exc:
            last_err = exc
            s = str(exc)
            if ("503" in s or "UNAVAILABLE" in s) and attempt < 2:
                time.sleep(1.5 * (attempt + 1))
                continue
            break

    if reply is None:
        s = str(last_err)
        if "429" in s or "RESOURCE_EXHAUSTED" in s:
            m = ("You've hit the daily AI limit for this model. Try again later, "
                 "switch GEMINI_MODEL in .env, or enable billing.")
        elif "503" in s or "UNAVAILABLE" in s:
            m = ("The AI model is busy right now (high demand). Give it a few "
                 "seconds and send your message again.")
        elif "404" in s or "NOT_FOUND" in s:
            m = "That model name isn't available for your key. Update GEMINI_MODEL in .env."
        else:
            m = f"The tutor hit an error: {s[:200]}"
        return jsonify(reply=m, kind="sys")

    dt = time.time() - t0
    store.add_message(uid, key, "user", safe)
    store.add_message(uid, key, "tutor", reply)
    store.log_event(event="chat", user=uid, challenge=key,
                    prompt_version=core.PROMPT_VERSION, mode=MODE, model=MODEL_NAME,
                    hint_level=prog["hint_level"], conversation_id=prog["conversation_id"],
                    response_time=dt, question=safe, reply=reply)
    return jsonify(reply=reply, kind="tutor")


@app.route("/challenge/<key>/reset", methods=["POST"])
@login_required
def reset_my_challenge(key):
    ch = get_challenge(key)
    if not ch:
        abort(404)
    store.reset_challenge(current_user_id(), key)
    flash("Your progress and chat for this challenge were reset.", "ok")
    return redirect(url_for("challenge", key=key))


@app.route("/challenge/<key>/download")
@login_required
def download(key):
    ch = get_challenge(key)
    if not ch or not ch["file_name"]:
        abort(404)
    return send_from_directory(FILES_DIR, ch["file_name"], as_attachment=True)


# ---------------------------------------------------------------------------
# Instructor moderation
# ---------------------------------------------------------------------------

def _require_instructor():
    if (session.get("user") or {}).get("role") != "instructor":
        abort(403)


def _challenge_name(key):
    c = core.CHALLENGES.get(key)
    return c["public"]["name"] if c else key


@app.route("/instructor")
@login_required
def instructor():
    _require_instructor()
    students = store.list_users()
    return render_template("instructor.html", students=students,
                           total=len(core.CHALLENGES))


@app.route("/instructor/user/<path:student>")
@login_required
def instructor_user(student):
    _require_instructor()
    summary = store.user_summary(student)
    for s in summary:
        s["name"] = _challenge_name(s["challenge"])
    summary.sort(key=lambda s: s["name"])
    return render_template("instructor_user.html", student=student, summary=summary)


@app.route("/instructor/user/<path:student>/<key>/transcript")
@login_required
def instructor_transcript(student, key):
    _require_instructor()
    messages = store.get_messages(student, key)
    return render_template("instructor_transcript.html", student=student,
                           key=key, name=_challenge_name(key), messages=messages)


@app.route("/instructor/reset", methods=["POST"])
@login_required
def instructor_reset():
    _require_instructor()
    student = request.form.get("student", "")
    key = request.form.get("challenge", "")
    if key:
        store.reset_challenge(student, key)
        flash(f"Reset {_challenge_name(key)} for {student}.", "ok")
        return redirect(url_for("instructor_user", student=student))
    store.reset_user(student)
    flash(f"Reset all progress for {student}.", "ok")
    return redirect(url_for("instructor"))


if __name__ == "__main__":
    app.run(host="localhost", port=5000, debug=True)