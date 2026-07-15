# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ai_common.py — Shared module for ZAP-AI scripts.
Supports Ollama (local) and OpenRouter (cloud) providers.
Place in ZAP's shared script folder or copy alongside each script.
"""
import json
import time
import threading
from java.net import URI
from java.net.http import HttpClient, HttpRequest, HttpResponse
from java.time import Duration

# ---- Provider defaults ----
OLLAMA_BASE_URL = "http://localhost:11434"
OPENROUTER_BASE_URL = "https://openrouter.ai/api"
DEFAULT_SERVICE = "ollama"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 120
DEFAULT_NUM_CTX = 32768
DEFAULT_MAX_TOKENS = 4096

# ---- Data classes ----
class ChatResult:
    def __init__(self, content, prompt_tokens=None, eval_tokens=None):
        self.content = content
        self.prompt_tokens = prompt_tokens
        self.eval_tokens = eval_tokens

class AiException(Exception):
    pass

class AiConfig:
    """Provider configuration for AI API calls."""
    def __init__(self, service=None, base_url=None, api_key="", model=None,
                 timeout=None, num_ctx=None, max_tokens=None):
        self.service = (service or DEFAULT_SERVICE).lower()
        self.base_url = (base_url or self._default_base_url()).rstrip('/')
        self.api_key = api_key
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout or DEFAULT_TIMEOUT
        self.num_ctx = num_ctx or DEFAULT_NUM_CTX
        self.max_tokens = max_tokens or DEFAULT_MAX_TOKENS

    def _default_base_url(self):
        return OPENROUTER_BASE_URL if self.service == "openrouter" else OLLAMA_BASE_URL

# ---- HTTP Client ----
_client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

def _json_dumps(obj):
    return json.dumps(obj, separators=(',', ':'))

def _extract_str(json_str, key):
    import re
    m = re.search(r'"' + re.escape(key) + r'"\s*:\s*"((?:[^"\\]|\\.)*)"', json_str)
    if m:
        return m.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t')
    return None

def _extract_int(json_str, key):
    import re
    m = re.search(r'"' + re.escape(key) + r'"\s*:\s*(-?\d+)', json_str)
    return int(m.group(1)) if m else None

def _send(req):
    """Send HTTP request and return response body string."""
    try:
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        if resp.statusCode() < 200 or resp.statusCode() >= 300:
            raise AiException("API returned {}: {}".format(resp.statusCode(), resp.body()))
        return resp.body()
    except AiException:
        raise
    except Exception as e:
        raise AiException("Request failed: {}".format(str(e)))

# ---- Health check ----
def health_check(config=None, **kwargs):
    """Check if the AI provider is reachable."""
    c = config or AiConfig(**kwargs)
    try:
        if c.service == "openrouter":
            req = HttpRequest.newBuilder() \
                .uri(URI.create("{}/v1/models".format(c.base_url))) \
                .timeout(Duration.ofSeconds(c.timeout)) \
                .header("Authorization", "Bearer {}".format(c.api_key)) \
                .GET().build()
        else:
            req = HttpRequest.newBuilder() \
                .uri(URI.create("{}/api/tags".format(c.base_url))) \
                .timeout(Duration.ofSeconds(c.timeout)) \
                .GET().build()
        _send(req)
        return True
    except:
        return False

# ---- List models ----
def list_models(config=None, **kwargs):
    """List available models from the AI provider."""
    c = config or AiConfig(**kwargs)
    try:
        if c.service == "openrouter":
            req = HttpRequest.newBuilder() \
                .uri(URI.create("{}/v1/models".format(c.base_url))) \
                .timeout(Duration.ofSeconds(c.timeout)) \
                .header("Authorization", "Bearer {}".format(c.api_key)) \
                .GET().build()
            body = _send(req)
            models = []
            import re
            # OpenRouter: {"data": [{"id": "model-name"}, ...]}
            for m in re.finditer(r'"id"\s*:\s*"([^"]+)"', body):
                models.append(m.group(1))
            return models
        else:
            req = HttpRequest.newBuilder() \
                .uri(URI.create("{}/api/tags".format(c.base_url))) \
                .timeout(Duration.ofSeconds(c.timeout)) \
                .GET().build()
            body = _send(req)
            models = []
            import re
            for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', body):
                models.append(m.group(1))
            return models
    except Exception as e:
        if isinstance(e, AiException):
            raise
        raise AiException("Failed to list models: {}".format(str(e)))

# ---- Chat ----
def _build_chat_request(config, messages, stream):
    """Build the appropriate HTTP request for the configured provider."""
    body = {"model": config.model, "messages": messages, "stream": stream}

    if config.service == "openrouter":
        if config.max_tokens:
            body["max_tokens"] = config.max_tokens
        builder = HttpRequest.newBuilder() \
            .uri(URI.create("{}/v1/chat/completions".format(config.base_url))) \
            .timeout(Duration.ofSeconds(config.timeout)) \
            .header("Content-Type", "application/json")
        if config.api_key:
            builder.header("Authorization", "Bearer {}".format(config.api_key))
        builder.POST(HttpRequest.BodyPublishers.ofString(_json_dumps(body)))
        return builder.build()
    else:
        if config.num_ctx:
            body["options"] = {"num_ctx": config.num_ctx}
        return HttpRequest.newBuilder() \
            .uri(URI.create("{}/api/chat".format(config.base_url))) \
            .timeout(Duration.ofSeconds(config.timeout)) \
            .header("Content-Type", "application/json") \
            .POST(HttpRequest.BodyPublishers.ofString(_json_dumps(body))) \
            .build()

def _parse_chat_response(config, response_body, stream, on_chunk):
    """Parse chat response based on provider format."""
    import re

    if config.service == "openrouter":
        if stream and on_chunk:
            for line in response_body.split('\n'):
                line = line.strip()
                if not line or not line.startswith("data: "):
                    continue
                data = line[6:]
                if data == "[DONE]":
                    continue
                content = _extract_str(data, "content")
                if content:
                    on_chunk(content)
            return ChatResult("", None, None)
        else:
            err = _extract_str(response_body, "error")
            if err:
                raise AiException(err)
            # OpenRouter: choices[0].message.content
            m = re.search(r'"choices"\s*:\s*\[.*?"message"\s*:\s*\{.*?"content"\s*:\s*"((?:[^"\\]|\\.)*)"', response_body)
            content = m.group(1).replace('\\n', '\n').replace('\\"', '"') if m else None
            if content is None:
                raise AiException("Empty response from OpenRouter")
            prompt_tokens = _extract_int(response_body, "prompt_tokens")
            eval_tokens = _extract_int(response_body, "completion_tokens")
            return ChatResult(content, prompt_tokens, eval_tokens)
    else:
        if stream and on_chunk:
            for line in response_body.split('\n'):
                line = line.strip()
                if not line:
                    continue
                err = _extract_str(line, "error")
                if err:
                    raise AiException(err)
                content = _extract_str(line, "content")
                if content:
                    on_chunk(content)
            return ChatResult("", None, None)
        else:
            err = _extract_str(response_body, "error")
            if err:
                raise AiException(err)
            content = _extract_str(response_body, "content")
            if content is None:
                m = re.search(r'"message"\s*:\s*\{[^}]*"content"\s*:\s*"((?:[^"\\]|\\.)*)"', response_body)
                if m:
                    content = m.group(1).replace('\\n', '\n').replace('\\"', '"')
            if content is None:
                raise AiException("Empty response from Ollama")
            prompt_tokens = _extract_int(response_body, "prompt_eval_count")
            eval_tokens = _extract_int(response_body, "eval_count")
            return ChatResult(content, prompt_tokens, eval_tokens)

def chat(model, system_prompt, user_message, config=None, **kwargs):
    """
    Send chat request to configured AI provider.

    Accepts either an AiConfig object or keyword args for config fields.
    If config is None and no kwargs given, uses defaults (Ollama local).
    If stream=True and on_chunk is provided, calls on_chunk(content) per token.
    Returns ChatResult on success, raises AiException on failure.
    """
    stream = kwargs.pop('stream', False)
    on_chunk = kwargs.pop('on_chunk', None) if stream else None

    c = config or AiConfig(**kwargs)
    messages = []
    if system_prompt and system_prompt.strip():
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})

    req = _build_chat_request(c, messages, stream)
    response_body = _send(req)
    return _parse_chat_response(c, response_body, stream, on_chunk)

# ---- Backward-compatible wrappers (Ollama-only signatures) ----
def ollama_chat(model, system_prompt, user_message, base_url=OLLAMA_BASE_URL,
                timeout=DEFAULT_TIMEOUT, num_ctx=None, stream=False, on_chunk=None):
    """Backward-compatible wrapper — delegates to chat() with Ollama config."""
    cfg = AiConfig(service="ollama", base_url=base_url, model=model,
                   timeout=timeout, num_ctx=num_ctx)
    return chat(model, system_prompt, user_message, config=cfg,
                stream=stream, on_chunk=on_chunk)

def ollama_list_models(base_url=OLLAMA_BASE_URL, timeout=DEFAULT_TIMEOUT):
    cfg = AiConfig(service="ollama", base_url=base_url, timeout=timeout)
    return list_models(config=cfg)

def ollama_health_check(base_url=OLLAMA_BASE_URL, timeout=DEFAULT_TIMEOUT):
    cfg = AiConfig(service="ollama", base_url=base_url, timeout=timeout)
    return health_check(config=cfg)

# ---- Formatting helpers ----
def format_error(error, config=None, **kwargs):
    """Format AI error into human-friendly message."""
    c = config or AiConfig(**kwargs)
    msg = str(error)
    svc = c.service.capitalize()

    if "not found" in msg.lower():
        import re
        m = re.search(r"model\s*['\"]?([^'\"]+)['\"]?", msg, re.IGNORECASE)
        name = m.group(1).strip() if m else c.model
        pull = "ollama pull {}".format(name) if c.service == "ollama" else "Check model name at openrouter.ai/models"
        return "Model '{}' not found.\n\nPull/Select:\n  {}".format(name, pull)
    if any(x in msg.lower() for x in ["connection refused", "connection reset", "no route to host"]):
        if c.service == "ollama":
            return "Cannot connect to Ollama at {}\n\n  Is Ollama running? Start: ollama serve".format(c.base_url)
        return "Cannot connect to OpenRouter at {}\n\n  Check your internet connection and API URL.".format(c.base_url)
    if "timeout" in msg.lower() or "timed out" in msg.lower():
        return "Request timed out. Try a smaller selection or increase timeout."
    if "unauthorized" in msg.lower() or "401" in msg or "403" in msg:
        if c.service == "openrouter":
            return "OpenRouter authentication failed. Check your API key."
        return "Authentication failed. Check your credentials."
    return "{}\n\nCheck {} at {}".format(msg, svc, c.base_url)

def security_prompts():
    """Return default security prompts."""
    return {
        "explain": "You are a security researcher, security engineer, and hacker. "
                   "Your task is to analyze and explain the content the user provides. "
                   "Be concise. Focus only on what is given.",
        "analyze": "You are a security researcher, security engineer, and hacker. "
                   "Your task is to analyze the provided content for security issues and vulnerabilities. "
                   "Be concise. Focus only on the content provided. Suggest remediation where relevant.",
        "validate_fp": "You are a security researcher, security engineer, and hacker. "
                       "Your task is to evaluate whether the finding is a real vulnerability or a false positive. "
                       "Answer with: Real / False positive / Uncertain, plus brief reasoning.",
        "decipher": "You are a security researcher, security engineer, and hacker. "
                    "Your task is to explain what the provided code or config does and identify security issues. "
                    "Be concise.",
        "explore": "You are a security researcher, security engineer, and hacker. "
                   "Your task is to suggest follow-up HTTP requests to validate or exploit the finding. "
                   "For each suggestion: 1) Goal. 2) Raw HTTP/1.1 in a markdown code block. Suggest 2-5 requests.",
    }

def build_report_snippet(text, template="default"):
    """Format AI response for vulnerability reports."""
    if template == "owasp":
        return "## Vulnerability Assessment (AI)\n\n{}\n\n---\n*Assessment generated by ZAP AI*".format(text.strip())
    return "## AI-Assisted Analysis\n\n{}\n\n---\n*Generated by ZAP AI Enrichment*".format(text.strip())

def truncate(text, max_chars=12000):
    """Truncate text for context window."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... [truncated, {} chars omitted]".format(len(text) - max_chars)

def format_alert(alert):
    """Format a ZAP Alert for AI analysis."""
    parts = [
    "## Scanner Finding: {}".format(alert.getName()),
    "**Severity:** {}".format(alert.getRisk().name()),
    "**Confidence:** {}".format(alert.getConfidence().name()),
    "**URL:** {}".format(alert.getUrl()),
    ]
    if alert.getDescription():
        parts.append("**Detail:** {}".format(alert.getDescription()))
    if alert.getSolution():
        parts.append("**Remediation:** {}".format(alert.getSolution()))
    if alert.getMessage():
        msg = alert.getMessage()
        req = msg.getRequestHeader().toString()
        parts.append("\n**Request:**\n{}".format(req[:2000]))
        resp = msg.getResponseHeader().toString()
        if resp:
            parts.append("\n**Response:**\n{}".format(resp[:2000]))
    return "\n".join(parts)

def extract_http_requests(text):
    """Extract HTTP requests from AI response (code blocks or raw)."""
    import re
    results = []
    for m in re.finditer(r'```(?:http)?\s*\n(.*?)```', text, re.DOTALL | re.IGNORECASE):
        block = m.group(1).strip()
        if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', block, re.IGNORECASE):
            results.append(block)
    if not results:
        lines = text.split('\n')
        i = 0
        while i < len(lines):
            if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', lines[i].strip(), re.IGNORECASE):
                buf = [lines[i]]
                i += 1
                while i < len(lines) and lines[i].strip():
                    buf.append(lines[i])
                    i += 1
                results.append('\n'.join(buf))
            else:
                i += 1
    return results
