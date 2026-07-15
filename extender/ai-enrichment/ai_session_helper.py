# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: AI Session Helper
Type: Session Management
Description: AI-assisted session handling for ZAP. Generates login sequences and maintains
             authenticated sessions using Ollama (local) or OpenRouter (cloud).
             Handles cookie extraction and request modification automatically.

Depends on: ai_common.py in same directory.

Configuration: Set via ScriptVars (or edit defaults below):
  - ai_session.service, ai_session.api_key, ai_session.base_url, ai_session.model
  - ai_session.login_url, ai_session.login_request_template, ai_session.login_description
  - ai_session.username, ai_session.password, ai_session.login_scope
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, format_error,
    AiConfig, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL,
    DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader, HttpSender
from org.zaproxy.zap.extension.script import ScriptVars
import re

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ai_session.{}".format(key))
        return val if val else default
    except:
        return default

SERVICE = _cfg("service", DEFAULT_SERVICE)
API_KEY = _cfg("api_key", "")
BASE_URL = _cfg("base_url", OLLAMA_BASE_URL if SERVICE == "ollama" else OPENROUTER_BASE_URL)
MODEL = _cfg("model", DEFAULT_MODEL)
TIMEOUT = int(_cfg("timeout", str(DEFAULT_TIMEOUT)))
NUM_CTX = int(_cfg("num_ctx", str(DEFAULT_NUM_CTX)))

_CONFIG = AiConfig(
    service=SERVICE, base_url=BASE_URL, api_key=API_KEY,
    model=MODEL, timeout=TIMEOUT, num_ctx=NUM_CTX
)

LOGIN_URL = _cfg("login_url", "")
LOGIN_REQUEST_TEMPLATE = _cfg("login_request_template", "")
USERNAME = _cfg("username", "")
PASSWORD = _cfg("password", "")
LOGIN_SCOPE = _cfg("login_scope", "")

LOGIN_GENERATION_PROMPT = (
    "You are a security researcher. Output a single raw HTTP/1.1 login request. "
    "Use {{username}} and {{password}} as placeholders. "
    "Include Host, Content-Type, and all required headers. "
    "Output ONLY the raw HTTP request, no explanation, no markdown."
)

_cookies = ""
_login_done = False
_lock = __import__('threading').Lock()


def _should_handle(msg):
    if not LOGIN_SCOPE.strip():
        return True
    try:
        url = str(msg.getRequestHeader().getURI())
        scope = LOGIN_SCOPE.strip().rstrip('/')
        return url.startswith(scope)
    except:
        return False


def _generate_login_request():
    if LOGIN_REQUEST_TEMPLATE.strip():
        return LOGIN_REQUEST_TEMPLATE

    description = _cfg("login_description", "")
    if not description.strip():
        print("[AI Session] No login template or description configured.")
        return None

    print("[AI Session] Generating login request from description...")
    try:
        result = chat(_CONFIG.model, LOGIN_GENERATION_PROMPT,
                      "Login flow description: {}".format(description), config=_CONFIG)
        raw = result.content.strip()
        m = re.search(r'```(?:http)?\s*\n(.*?)```', raw, re.DOTALL)
        if m:
            raw = m.group(1).strip()
        print("[AI Session] Generated login request:\n{}".format(raw[:500]))
        return raw
    except Exception as e:
        print("[AI Session] Failed to generate login: {}".format(format_error(e, _CONFIG)))
        return None


def _perform_login():
    global _cookies, _login_done

    template = _generate_login_request()
    if not template:
        return False

    request_str = template.replace("{{username}}", USERNAME).replace("{{password}}", PASSWORD)

    try:
        msg = HttpMessage()
        msg.setRequestHeader(HttpRequestHeader(request_str))
        sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
        sender.sendAndReceive(msg)

        cookies = []
        resp_headers = msg.getResponseHeader()
        if resp_headers:
            for i in range(resp_headers.getHeaderLines().size()):
                header = resp_headers.getHeaderLines().get(i)
                if header and header.getName().lower() == "set-cookie":
                    cookie_val = header.getValue()
                    name_val = cookie_val.split(';')[0].strip()
                    cookies.append(name_val)

            _cookies = "; ".join(cookies)
            if _cookies:
                _login_done = True
                print("[AI Session] Login successful. Cookies: {}".format(_cookies[:200]))
                return True
            else:
                print("[AI Session] Login response had no Set-Cookie headers.")
                return False
        else:
            print("[AI Session] No response from login request.")
            return False
    except Exception as e:
        print("[AI Session] Login failed: {}".format(str(e)))
        return False


def _add_cookies(msg):
    if not _cookies:
        return
    try:
        msg.getRequestHeader().setHeader("Cookie", _cookies)
    except Exception as e:
        print("[AI Session] Failed to add cookies: {}".format(str(e)))


# ---- ZAP Session Management Hook ----
def authenticate(msg):
    global _login_done

    if not _should_handle(msg):
        return msg

    with _lock:
        if not _login_done:
            success = _perform_login()
            if not success:
                print("[AI Session] Auth failed, proceeding without cookies.")
                return msg
        if _cookies:
            _add_cookies(msg)

    return msg


def getName():
    return "AI Session Helper"


def getDescription():
    return "AI-assisted session handling (Ollama or OpenRouter) for login sequence generation"


# ---- Console test helpers ----
def test_login():
    global _login_done, _cookies
    _login_done = False
    _cookies = ""
    success = _perform_login()
    print("Login: {}".format(success))
    print("Cookies: {}".format(_cookies))


def reset_session():
    global _login_done, _cookies
    _login_done = False
    _cookies = ""
    print("[AI Session] Session reset.")


def set_description(desc):
    ScriptVars.setGlobalVar("ai_session.login_description", desc)
    print("[AI Session] Description saved.")
