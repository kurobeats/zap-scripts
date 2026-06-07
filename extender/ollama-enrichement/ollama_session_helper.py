"""
ZAP Script: Ollama Session Helper
Type: Session Management
Description: AI-assisted session handling for ZAP. Uses Ollama to generate login sequences
             and maintain authenticated sessions. The script handles cookie extraction and
             request modification automatically.

Place ollama_common.py in the same directory or ZAP's shared scripts folder.

Configuration: Set via ScriptVars (or edit defaults below):
  - ollama_session.base_url
  - ollama_session.model
  - ollama_session.login_url
  - ollama_session.login_request_template
  - ollama_session.username
  - ollama_session.password
  - ollama_session.login_scope (base URL to limit session handling)

Usage: Add this as a Session Management script in ZAP > Session Properties > Session Management.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ollama_common import (
    chat, format_error, DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX, OllamaException
)
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader, HttpSender
from org.zaproxy.zap.extension.script import ScriptVars
import re

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ollama_session.{}".format(key))
        return val if val else default
    except:
        return default

BASE_URL = _cfg("base_url", DEFAULT_BASE_URL)
MODEL = _cfg("model", DEFAULT_MODEL)
TIMEOUT = int(_cfg("timeout", str(DEFAULT_TIMEOUT)))
NUM_CTX = int(_cfg("num_ctx", str(DEFAULT_NUM_CTX)))

LOGIN_URL = _cfg("login_url", "")
LOGIN_REQUEST_TEMPLATE = _cfg("login_request_template", "")
USERNAME = _cfg("username", "")
PASSWORD = _cfg("password", "")
LOGIN_SCOPE = _cfg("login_scope", "")  # Only handle requests to this base URL

# System prompt for login sequence generation
LOGIN_GENERATION_PROMPT = (
    "You are a security researcher. Output a single raw HTTP/1.1 login request. "
    "Use {{username}} and {{password}} as placeholders. "
    "Include Host, Content-Type, and all required headers. "
    "Output ONLY the raw HTTP request, no explanation, no markdown."
)

# ---- State ----
_cookies = ""  # Cached session cookies
_login_done = False
_lock = __import__('threading').Lock()


def _should_handle(msg):
    """Check if this request falls within our login scope."""
    if not LOGIN_SCOPE.strip():
        return True  # Handle all requests if no scope set
    try:
        url = str(msg.getRequestHeader().getURI())
        scope = LOGIN_SCOPE.strip().rstrip('/')
        return url.startswith(scope)
    except:
        return False


def _generate_login_request():
    """Use Ollama to generate a login HTTP request from a description."""
    if LOGIN_REQUEST_TEMPLATE.strip():
        return LOGIN_REQUEST_TEMPLATE

    description = _cfg("login_description", "")
    if not description.strip():
        print("[Ollama Session] No login template or description configured.")
        return None

    print("[Ollama Session] Generating login request from description...")
    try:
        result = chat(MODEL, LOGIN_GENERATION_PROMPT,
                      "Login flow description: {}".format(description),
                      BASE_URL, TIMEOUT, NUM_CTX, stream=False)
        raw = result.content.strip()
        # Extract HTTP request from possible markdown code block
        m = re.search(r'```(?:http)?\s*\n(.*?)```', raw, re.DOTALL)
        if m:
            raw = m.group(1).strip()
        print("[Ollama Session] Generated login request:\n{}".format(raw[:500]))
        return raw
    except Exception as e:
        print("[Ollama Session] Failed to generate login: {}".format(
            format_error(e, BASE_URL, MODEL)))
        return None


def _perform_login():
    """Execute the login request and extract session cookies."""
    global _cookies, _login_done

    template = _generate_login_request()
    if not template:
        return False

    # Substitute placeholders
    request_str = template.replace("{{username}}", USERNAME).replace("{{password}}", PASSWORD)

    try:
        msg = HttpMessage()
        msg.setRequestHeader(HttpRequestHeader(request_str))
        sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
        sender.sendAndReceive(msg)

        # Extract Set-Cookie headers
        cookies = []
        resp_headers = msg.getResponseHeader()
        if resp_headers:
            for i in range(resp_headers.getHeaderLines().size()):
                header = resp_headers.getHeaderLines().get(i)
                if header and header.getName().lower() == "set-cookie":
                    cookie_val = header.getValue()
                    # Take just the name=value part (before first ;)
                    name_val = cookie_val.split(';')[0].strip()
                    cookies.append(name_val)

            _cookies = "; ".join(cookies)
            if _cookies:
                _login_done = True
                print("[Ollama Session] Login successful. Cookies: {}".format(_cookies[:200]))
                return True
            else:
                print("[Ollama Session] Login response had no Set-Cookie headers.")
                return False
        else:
            print("[Ollama Session] No response from login request.")
            return False
    except Exception as e:
        print("[Ollama Session] Login failed: {}".format(str(e)))
        return False


def _add_cookies(msg):
    """Add session cookies to the request."""
    if not _cookies:
        return
    try:
        req_header = msg.getRequestHeader()
        req_header.setHeader("Cookie", _cookies)
    except Exception as e:
        print("[Ollama Session] Failed to add cookies: {}".format(str(e)))


# ---- ZAP Session Management Hook ----
def authenticate(msg):
    """
    Called by ZAP before each request is sent.
    Returns the (possibly modified) HttpMessage.
    """
    global _login_done

    if not _should_handle(msg):
        return msg

    with _lock:
        if not _login_done:
            success = _perform_login()
            if not success:
                print("[Ollama Session] Authentication failed, proceeding without cookies.")
                return msg

        if _cookies:
            _add_cookies(msg)

    return msg


def getName():
    return "Ollama Session Helper"


def getDescription():
    return "AI-assisted session handling using Ollama for login sequence generation"


# ---- Console test helper ----
def test_login():
    """Test login generation (run from Script Console)."""
    global _login_done, _cookies
    _login_done = False
    _cookies = ""
    success = _perform_login()
    print("Login result: {}".format(success))
    print("Cookies: {}".format(_cookies))


def reset_session():
    """Reset session state (run from Script Console to force re-login)."""
    global _login_done, _cookies
    _login_done = False
    _cookies = ""
    print("[Ollama Session] Session reset.")


def set_description(desc):
    """Set login description and save to config."""
    try:
        ScriptVars.setGlobalVar("ollama_session.login_description", desc)
        print("[Ollama Session] Login description saved.")
    except:
        pass
