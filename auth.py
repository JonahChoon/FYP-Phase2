"""
auth.py -- online sign-in for the CTF Tutor web app (GitHub / Google OAuth).

No passwords stored. Users sign in with an account they already have; we read
their name + email from the provider and keep it in the session. A demo button
lets the site run before any OAuth is configured.

Config (in .env):
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET      -> enables "Continue with GitHub"
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET      -> enables "Continue with Google"
  MS_CLIENT_ID / MS_CLIENT_SECRET              -> enables "Continue with Microsoft"
  MS_TENANT=common                             -> "common" = any Microsoft account (default)
  INSTRUCTOR_EMAILS=a@x.com,b@y.com            -> these emails get the instructor role
  ALLOW_DEMO=1                                 -> show the demo sign-in button (default on)

Redirect URIs to register with each provider:
  GitHub:     http://localhost:5000/auth/github
  Google:     http://localhost:5000/auth/google
  Microsoft:  http://localhost:5000/auth/microsoft
"""

import os

from authlib.integrations.flask_client import OAuth
from flask import flash, redirect, render_template, request, session, url_for

GITHUB_ID = os.environ.get("GITHUB_CLIENT_ID", "")
GITHUB_SECRET = os.environ.get("GITHUB_CLIENT_SECRET", "")
GOOGLE_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
MS_ID = os.environ.get("MS_CLIENT_ID", "")
MS_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
MS_TENANT = os.environ.get("MS_TENANT", "common")
INSTRUCTOR_EMAILS = {e.strip().lower()
                     for e in os.environ.get("INSTRUCTOR_EMAILS", "").split(",") if e.strip()}
ALLOW_DEMO = os.environ.get("ALLOW_DEMO", "1").lower() in ("1", "true", "yes")

oauth = OAuth()


def providers() -> list:
    p = []
    if GITHUB_ID and GITHUB_SECRET:
        p.append("github")
    if GOOGLE_ID and GOOGLE_SECRET:
        p.append("google")
    if MS_ID and MS_SECRET:
        p.append("microsoft")
    return p


def _role_for(email: str) -> str:
    return "instructor" if (email or "").lower() in INSTRUCTOR_EMAILS else "student"


def _set_user(name, email, provider, avatar=""):
    session["user"] = {
        "name": name or email or "User",
        "email": email or "",
        "provider": provider,
        "avatar": avatar or "",
        "role": _role_for(email),
    }


def init_auth(app):
    oauth.init_app(app)
    if GITHUB_ID and GITHUB_SECRET:
        oauth.register(
            "github", client_id=GITHUB_ID, client_secret=GITHUB_SECRET,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "read:user user:email"})
    if GOOGLE_ID and GOOGLE_SECRET:
        oauth.register(
            "google", client_id=GOOGLE_ID, client_secret=GOOGLE_SECRET,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"})
    if MS_ID and MS_SECRET:
        oauth.register(
            "microsoft", client_id=MS_ID, client_secret=MS_SECRET,
            server_metadata_url=(f"https://login.microsoftonline.com/{MS_TENANT}"
                                 "/v2.0/.well-known/openid-configuration"),
            client_kwargs={"scope": "openid email profile"})
    _routes(app)


def _routes(app):
    @app.route("/login")
    def login():
        if "user" in session:
            return redirect(url_for("index"))
        return render_template("login.html", providers=providers(), allow_demo=ALLOW_DEMO)

    @app.route("/login/<provider>")
    def login_provider(provider):
        if provider not in providers():
            flash("That sign-in option isn't configured.", "err")
            return redirect(url_for("login"))
        client = oauth.create_client(provider)
        return client.authorize_redirect(
            url_for("auth_callback", provider=provider, _external=True))

    @app.route("/auth/<provider>")
    def auth_callback(provider):
        if provider not in providers():
            return redirect(url_for("login"))
        client = oauth.create_client(provider)
        try:
            token = client.authorize_access_token()
        except Exception:
            flash("Sign-in was cancelled or failed. Please try again.", "err")
            return redirect(url_for("login"))

        if provider in ("google", "microsoft"):  # OIDC providers
            info = token.get("userinfo") or {}
            email = info.get("email") or info.get("preferred_username")
            _set_user(info.get("name"), email, provider, info.get("picture"))
        else:  # github
            prof = client.get("user").json()
            email = prof.get("email")
            if not email:  # email may be private; fetch the primary verified one
                try:
                    emails = client.get("user/emails").json()
                    if isinstance(emails, list):
                        email = next((e["email"] for e in emails
                                      if e.get("primary") and e.get("verified")), None) \
                                or (emails[0]["email"] if emails else "")
                except Exception:
                    email = ""
            _set_user(prof.get("name") or prof.get("login"), email, "github",
                      prof.get("avatar_url"))
        return redirect(url_for("index"))

    @app.route("/login/demo")
    def login_demo():
        if not ALLOW_DEMO:
            return redirect(url_for("login"))
        role = "instructor" if request.args.get("role") == "instructor" else "student"
        session["user"] = {"name": f"Demo {role}", "email": "demo@example.edu",
                           "provider": "demo", "avatar": "", "role": role}
        return redirect(url_for("index"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))