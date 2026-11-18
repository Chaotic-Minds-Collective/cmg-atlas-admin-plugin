import html
import json
import os
import secrets
import socket
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx
import yaml
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from valve.source.a2s import NoResponseError, ServerQuerier

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
session_secret = os.environ.get("SESSION_SECRET", "")
if len(session_secret) < 32 or not session_secret.strip():
    raise RuntimeError("SESSION_SECRET must be set to a random value of at least 32 characters")
discord_client_secret = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
if not discord_client_secret:
    raise RuntimeError("DISCORD_CLIENT_SECRET must be set")
with (BASE_DIR / "config.yaml").open(encoding="utf-8") as config_file:
    config = yaml.safe_load(config_file)


def parse_allowed_origins(raw):
    origins = []
    for value in raw.split(","):
        candidate = value.strip()
        if not candidate:
            continue
        try:
            parsed = urlsplit(candidate)
            parsed.port
        except ValueError as error:
            raise RuntimeError("ADMIN_ALLOWED_ORIGINS contains an invalid origin") from error
        if (parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname
                or "*" in parsed.netloc or parsed.username is not None or parsed.password is not None
                or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
            raise RuntimeError("ADMIN_ALLOWED_ORIGINS requires exact HTTP(S) origins without wildcards or paths")
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if origin not in origins:
            origins.append(origin)
    return origins


def parse_bool_env(name, default):
    value = os.environ.get(name, default).strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be true or false")


allowed_origins = parse_allowed_origins(os.environ.get("ADMIN_ALLOWED_ORIGINS", ""))
session_cookie_secure = parse_bool_env("SESSION_COOKIE_SECURE", "true")
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=session_secret, max_age=8 * 60 * 60,
                   same_site="lax", https_only=session_cookie_secure)
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=True,
                   allow_methods=["GET"], allow_headers=["Content-Type"])
DISCORD_API = "https://discord.com/api"
ALLOWED_USERS = [str(user_id) for user_id in config["discord"]["allowed_users"]]


def is_admin(session):
    user = session.get("user")
    return isinstance(user, dict) and user.get("id") in ALLOWED_USERS


@app.get("/")
def home(request: Request):
    if not is_admin(request.session):
        return RedirectResponse("/login")
    username = html.escape(str(request.session["user"].get("username", "")), quote=True)
    return HTMLResponse(f"<h2>Welcome, {username}</h2><a href='/logout'>Logout</a>")


@app.get("/login")
def login(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["discord_oauth_state"] = state
    request.session["discord_oauth_issued_at"] = time.time()
    query = urlencode({"client_id": config["discord"]["client_id"],
                       "redirect_uri": config["discord"]["redirect_uri"],
                       "response_type": "code", "scope": "identify", "state": state})
    return RedirectResponse(f"{DISCORD_API}/oauth2/authorize?{query}")


def consume_oauth_state(request, state):
    expected = request.session.pop("discord_oauth_state", None)
    issued = request.session.pop("discord_oauth_issued_at", None)
    if (not isinstance(expected, str) or not expected or not expected.isascii()
            or not isinstance(state, str) or not state or len(state) > 512 or not state.isascii()
            or not isinstance(issued, (int, float)) or isinstance(issued, bool)
            or not 0 <= time.time() - issued <= 600
            or not secrets.compare_digest(state, expected)):
        raise HTTPException(status_code=400, detail="Invalid or expired OAuth state")


async def auth_callback(code: str, request: Request):
    """Provider exchange helper; the HTTP route below validates browser state first."""
    data = {"client_id": config["discord"]["client_id"], "client_secret": discord_client_secret,
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": config["discord"]["redirect_uri"]}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_response = await client.post(f"{DISCORD_API}/oauth2/token", data=data)
            token_response.raise_for_status()
            token_data = token_response.json()
            if not isinstance(token_data, dict):
                raise HTTPException(status_code=502, detail="Discord authentication request failed")
            token = token_data.get("access_token")
            if not token:
                raise HTTPException(status_code=502, detail="Discord did not return an access token")
            if not isinstance(token, str) or not token.strip():
                raise HTTPException(status_code=502, detail="Discord authentication request failed")
            user_response = await client.get(f"{DISCORD_API}/users/@me", headers={"Authorization": f"Bearer {token}"})
            user_response.raise_for_status()
            user = user_response.json()
            if (not isinstance(user, dict) or not isinstance(user.get("id"), str)
                    or not user["id"].strip() or not isinstance(user.get("username", ""), str)):
                raise HTTPException(status_code=502, detail="Discord authentication request failed")
            request.session["user"] = {"id": user["id"], "username": user.get("username", "")}
    except (httpx.HTTPError, json.JSONDecodeError, KeyError) as error:
        raise HTTPException(status_code=502, detail="Discord authentication request failed") from error
    return RedirectResponse("/")


@app.get("/auth/callback")
async def oauth_callback(code: str, request: Request, state: str = ""):
    consume_oauth_state(request, state)
    response = await auth_callback(code, request)
    if not is_admin(request.session):
        request.session.clear()
        raise HTTPException(status_code=403, detail="This account is not authorized for the admin panel")
    return response


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login")


@app.get("/api/status")
def status(request: Request):
    if not is_admin(request.session):
        raise HTTPException(status_code=403)
    return {grid["id"]: is_port_open(grid["port"]) for grid in config["grids"]}


@app.get("/api/players")
def players(request: Request):
    if not is_admin(request.session):
        raise HTTPException(status_code=403)
    results = {}
    for grid in config["grids"]:
        try:
            with ServerQuerier(("127.0.0.1", grid["port"]), timeout=1) as server:
                info = server.info()
                player_info = server.players()
                results[grid["id"]] = {"name": info["server_name"], "map": info["map"],
                    "players": player_info["players"], "max_players": info["max_players"]}
        except NoResponseError:
            results[grid["id"]] = {"error": "No response"}
        except Exception as error:
            results[grid["id"]] = {"error": str(error)}
    return results


def is_port_open(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(0.5)
        return connection.connect_ex(("127.0.0.1", port)) == 0


@app.get("/api/leaderboard")
def leaderboard():
    with (BASE_DIR / "data" / "leaderboard.json").open(encoding="utf-8") as leaderboard_file:
        return json.load(leaderboard_file)
