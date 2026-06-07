"""
ZAP Script: Ollama Session Helper Enhanced
Type: Session Management
Description: Enhanced session handling with multi-model login generation, streaming generation,
             session validation, and auto-reauthentication on session expiry.

Depends on: ollama_common_enhanced.py
"""
import sys, os, re, threading, time
sys.path.append(os.path.dirname(__file__))

from ollama_common_enhanced import (
    chat, format_error, PROMPT_TEMPLATES,
    DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX, OllamaException
)
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader, HttpSender
from org.zaproxy.zap.extension.script import ScriptVars

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ollama_session2.{}".format(key))
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
LOGIN_SCOPE = _cfg("login_scope", "")

# Session validation: periodically check if session is still valid
SESSION_CHECK_INTERVAL = int(_cfg("session_check_interval", "0"))  # 0 = disabled, seconds
SESSION_CHECK_URL = _cfg("session_check_url", "")  # URL to probe for session validity

# Streaming login generation
STREAM_LOGIN_GENERATION = _cfg("stream_generation", "false") == "true"

# Multi-model: use a different (lighter) model for session validation
VALIDATION_MODEL = _cfg("validation_model", MODEL)

# ---- State ----
_cookies = ""
_login_done = False
_last_login_time = 0
_lock = threading.Lock()
_session_checker_running = False

# System prompt for login generation
LOGIN_GENERATION_PROMPT = (
    "You are a security researcher. Output a single raw HTTP/1.1 login request. "
    "Use {{username}} and {{password}} as placeholders. "
    "Include Host, Content-Type, and all required headers. "
    "Output ONLY the raw HTTP request, no explanation, no markdown."
)

# System prompt for session validation
SESSION_VALIDATION_PROMPT = (
    "You are a security researcher. Given the login response below, determine if the "
    "session appears valid. A valid session typically returns a 200/302 status, session "
    "cookies, or a logged-in page. Output exactly: VALID or INVALID, then one-line reason."
)


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
    """Use Ollama to generate a login HTTP request from a description, with streaming."""
    if LOGIN_REQUEST_TEMPLATE.strip():
        return LOGIN_REQUEST_TEMPLATE

    description = _cfg("login_description", "")
    if not description.strip():
        print("[OllamaSession+] No login template or description configured.")
        return None

    print("[OllamaSession+] Generating login request...")
    try:
        if STREAM_LOGIN_GENERATION:
            tokens = []
            def on_chunk(chunk):
                tokens.append(chunk)
                print(chunk, end='')
            chat(MODEL, LOGIN_GENERATION_PROMPT,
                 "Login flow description: {}".format(description),
                 BASE_URL, TIMEOUT, NUM_CTX, stream=True, on_chunk=on_chunk)
            raw = ''.join(tokens).strip()
            print("")
        else:
            result = chat(MODEL, LOGIN_GENERATION_PROMPT,
                          "Login flow description: {}".format(description),
                          BASE_URL, TIMEOUT, NUM_CTX, stream=False)
            raw = result.content.strip()

        # Extract from markdown code block
        m = re.search(r'```(?:http)?\s*\n(.*?)```', raw, re.DOTALL | re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
        print("[OllamaSession+] Generated {} chars.".format(len(raw)))
        return raw
    except Exception as e:
        print("[OllamaSession+] Generation failed: {}".format(format_error(e, BASE_URL, MODEL)))
        return None


def _validate_session():
    """
    Check if the current session is still valid by sending a probe request.
    Returns True if session appears valid.
    """
    global _cookies
    if not _cookies or not SESSION_CHECK_URL.strip():
        return True  # Can't validate, assume ok

    try:
        msg = HttpMessage()
        msg.setRequestHeader(HttpRequestHeader(
            "GET {} HTTP/1.1\r\nHost: {}\r\nCookie: {}\r\n\r\n".format(
                SESSION_CHECK_URL, re.sub(r'https?://([^/]+).*', r'\1', SESSION_CHECK_URL), _cookies
            )
        ))
        sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
        sender.sendAndReceive(msg)

        resp = msg.getResponseHeader()
        if resp:
            status = resp.getStatusCode()
            body = str(msg.getResponseBody())[:1000]

            # Quick heuristic: 200 with no redirect/login page
            if status == 200 and "login" not in body.lower()[:500]:
                return True
            if status in (301, 302):
                # Check if redirect goes to login page
                location = resp.getHeader("Location")
                if location and "login" in location.lower():
                    return False
                return True
            if status == 401 or status == 403:
                return False

            # AI-based validation
            try:
                result = chat(
                    VALIDATION_MODEL, SESSION_VALIDATION_PROMPT,
                    "Response status: {}\nHeaders: {}\nBody: {}".format(
                        status, str(resp)[:500], body
                    ),
                    BASE_URL, min(TIMEOUT, 30), NUM_CTX
                )
                return "VALID" in result.content.upper() and "INVALID" not in result.content.upper()
            except:
                pass
        return True
    except Exception as e:
        print("[OllamaSession+] Validation error: {}".format(str(e)))
        return True


def _perform_login():
    global _cookies, _login_done, _last_login_time

    template = _generate_login_request()
    if not template:
        return False

    request_str = template.replace("{{username}}", USERNAME).replace("{{password}}", PASSWORD)

    try:
        msg = HttpMessage()
        msg.setRequestHeader(HttpRequestHeader(request_str))
        sender = HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR)
        sender.sendAndReceive(msg)

        resp_headers = msg.getResponseHeader()
        if not resp_headers:
            print("[OllamaSession+] No response from login request.")
            return False

        cookies = []
        for i in range(resp_headers.getHeaderLines().size()):
            header = resp_headers.getHeaderLines().get(i)
            if header and str(header.getName()).lower() == "set-cookie":
                cookie_val = str(header.getValue())
                name_val = cookie_val.split(';')[0].strip()
                cookies.append(name_val)

        if cookies:
            _cookies = "; ".join(cookies)
            _login_done = True
            _last_login_time = time.time()
            print("[OllamaSession+] Login successful ({} cookies).".format(len(cookies)))
            self._maybe_start_session_checker()
            return True
        else:
            print("[OllamaSession+] Login response had no Set-Cookie. Status: {}".format(
                resp_headers.getStatusCode()))
            return False
    except Exception as e:
        print("[OllamaSession+] Login failed: {}".format(str(e)))
        return False


def _add_cookies(msg):
    if not _cookies:
        return
    try:
        msg.getRequestHeader().setHeader("Cookie", _cookies)
    except Exception as e:
        print("[OllamaSession+] Cookie injection failed: {}".format(str(e)))


def _maybe_start_session_checker():
    """Start periodic session validation if configured."""
    global _session_checker_running
    if SESSION_CHECK_INTERVAL <= 0 or _session_checker_running:
        return
    _session_checker_running = True

    def checker():
        while True:
            time.sleep(SESSION_CHECK_INTERVAL)
            global _login_done, _cookies
            with _lock:
                if not _login_done:
                    continue
                valid = _validate_session()
                if not valid:
                    print("[OllamaSession+] Session expired, re-authenticating...")
                    _login_done = False
                    _cookies = ""
                    _perform_login()

    threading.Thread(target=checker, daemon=True).start()
    print("[OllamaSession+] Session checker started (interval: {}s).".format(SESSION_CHECK_INTERVAL))


# ---- ZAP Session Management Hook ----
def authenticate(msg):
    global _login_done

    if not _should_handle(msg):
        return msg

    with _lock:
        if not _login_done:
            success = _perform_login()
            if not success:
                return msg
        _add_cookies(msg)

    return msg


def getName():
    return "Ollama Session Helper Enhanced"


def getDescription():
    return "Enhanced AI session handling: streaming login generation, session validation, auto-reauth"


# ---- Console helpers ----
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
    print("[OllamaSession+] Reset.")


def check_session():
    valid = _validate_session()
    print("[OllamaSession+] Session valid: {}".format(valid))


def set_description(desc):
    ScriptVars.setGlobalVar("ollama_session2.login_description", desc)
    print("[OllamaSession+] Description saved.")
