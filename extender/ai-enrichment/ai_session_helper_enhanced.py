# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: AI Session Helper Enhanced
Type: Session Management
Description: Enhanced session handling with multi-model login generation, streaming generation,
             session validation, and auto-reauthentication on session expiry.
             Supports Ollama (local) and OpenRouter (cloud).

Depends on: ai_common.py, ai_common_enhanced.py in same directory.
"""
import sys, os, re, threading, time
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, format_error,
    AiConfig, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL,
    DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from ai_common_enhanced import PROMPT_TEMPLATES
from org.parosproxy.paros.network import HttpMessage, HttpRequestHeader, HttpSender
from org.zaproxy.zap.extension.script import ScriptVars

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ai_session2.{}".format(key))
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

LOGIN_REQUEST_TEMPLATE = _cfg("login_request_template", "")
USERNAME = _cfg("username", "")
PASSWORD = _cfg("password", "")
LOGIN_SCOPE = _cfg("login_scope", "")

SESSION_CHECK_INTERVAL = int(_cfg("session_check_interval", "300"))
SESSION_CHECK_URL = _cfg("session_check_url", "")
STREAM_LOGIN_GENERATION = _cfg("stream_generation", "false") == "true"
VALIDATION_MODEL = _cfg("validation_model", MODEL)

_cookies = ""
_login_done = False
_last_login_time = 0
_lock = threading.Lock()
_session_checker_running = False

LOGIN_GENERATION_PROMPT = (
    "You are a security researcher. Output a single raw HTTP/1.1 login request. "
    "Use {{username}} and {{password}} as placeholders. "
    "Include Host, Content-Type, and all required headers. "
    "Output ONLY the raw HTTP request, no explanation, no markdown."
)

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
    if LOGIN_REQUEST_TEMPLATE.strip():
        return LOGIN_REQUEST_TEMPLATE

    description = _cfg("login_description", "")
    if not description.strip():
        print("[AiSession+] No login template or description configured.")
        return None

    print("[AiSession+] Generating login request...")
    try:
        if STREAM_LOGIN_GENERATION:
            tokens = []
            def on_chunk(chunk):
                tokens.append(chunk)
                print(chunk, end='')
            chat(_CONFIG.model, LOGIN_GENERATION_PROMPT,
                 "Login flow description: {}".format(description),
                 config=_CONFIG, stream=True, on_chunk=on_chunk)
            raw = ''.join(tokens).strip()
            print("")
        else:
            result = chat(_CONFIG.model, LOGIN_GENERATION_PROMPT,
                          "Login flow description: {}".format(description), config=_CONFIG)
            raw = result.content.strip()

        m = re.search(r'```(?:http)?\s*\n(.*?)```', raw, re.DOTALL | re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
        print("[AiSession+] Generated {} chars.".format(len(raw)))
        return raw
    except Exception as e:
        print("[AiSession+] Generation failed: {}".format(format_error(e, _CONFIG)))
        return None


def _validate_session():
    global _cookies
    if not _cookies or not SESSION_CHECK_URL.strip():
        return True

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

            if status == 200 and "login" not in body.lower()[:500]:
                return True
            if status in (301, 302):
                location = resp.getHeader("Location")
                if location and "login" in location.lower():
                    return False
                return True
            if status == 401 or status == 403:
                return False

            try:
                vcfg = AiConfig(service=SERVICE, base_url=BASE_URL, api_key=API_KEY,
                                model=VALIDATION_MODEL, timeout=min(TIMEOUT, 30), num_ctx=NUM_CTX)
                result = chat(vcfg.model, SESSION_VALIDATION_PROMPT,
                              "Response status: {}\nHeaders: {}\nBody: {}".format(
                                  status, str(resp)[:500], body), config=vcfg)
                return "VALID" in result.content.upper() and "INVALID" not in result.content.upper()
            except:
                pass
        return True
    except Exception as e:
        print("[AiSession+] Validation error: {}".format(str(e)))
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
            print("[AiSession+] No response from login request.")
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
            print("[AiSession+] Login successful ({} cookies).".format(len(cookies)))
            _maybe_start_session_checker()
            return True
        else:
            print("[AiSession+] Login response had no Set-Cookie. Status: {}".format(
                resp_headers.getStatusCode()))
            return False
    except Exception as e:
        print("[AiSession+] Login failed: {}".format(str(e)))
        return False


def _add_cookies(msg):
    if not _cookies:
        return
    try:
        msg.getRequestHeader().setHeader("Cookie", _cookies)
    except Exception as e:
        print("[AiSession+] Cookie injection failed: {}".format(str(e)))


def _maybe_start_session_checker():
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
                    print("[AiSession+] Session expired, re-authenticating...")
                    _login_done = False
                    _cookies = ""
                    _perform_login()

    threading.Thread(target=checker, daemon=True).start()
    print("[AiSession+] Session checker started (interval: {}s).".format(SESSION_CHECK_INTERVAL))


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
    return "AI Session Helper Enhanced"


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
    print("[AiSession+] Reset.")


def check_session():
    valid = _validate_session()
    print("[AiSession+] Session valid: {}".format(valid))


def set_description(desc):
    ScriptVars.setGlobalVar("ai_session2.login_description", desc)
    print("[AiSession+] Description saved.")
