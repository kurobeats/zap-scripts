"""
ollama_common.py — Shared module for ZAP-Ollama scripts.
Place in ZAP's shared script folder or copy alongside each script.
"""
import json
import time
import threading
from java.net import URI
from java.net.http import HttpClient, HttpRequest, HttpResponse
from java.time import Duration

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:3b"
DEFAULT_TIMEOUT = 120
DEFAULT_NUM_CTX = 32768

# ---- Data classes ---- 
class ChatResult:
    def __init__(self, content, prompt_tokens=None, eval_tokens=None):
        self.content = content
        self.prompt_tokens = prompt_tokens
        self.eval_tokens = eval_tokens

class OllamaException(Exception):
    pass

# ---- HTTP Client ----
def _build_client():
    return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

_client = _build_client()

def _json_dumps(obj):
    """Minimal JSON serializer for chat requests."""
    return json.dumps(obj, separators=(',', ':'))

def _parse_json_string(json_str, key):
    """Extract a string value for key from JSON without full parsing."""
    import re
    pattern = r'"' + re.escape(key) + r'"\s*:\s*"((?:[^"\\]|\\.)*)"'
    m = re.search(pattern, json_str)
    if m:
        return m.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t')
    return None

def _parse_json_int(json_str, key):
    import re
    pattern = r'"' + re.escape(key) + r'"\s*:\s*(-?\d+)'
    m = re.search(pattern, json_str)
    if m:
        return int(m.group(1))
    return None

def health_check(base_url=DEFAULT_BASE_URL, timeout=DEFAULT_TIMEOUT):
    """Check if Ollama is reachable."""
    try:
        req = HttpRequest.newBuilder() \
            .uri(URI.create("{}/api/tags".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)) \
            .GET().build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        return 200 <= resp.statusCode() < 300
    except:
        return False

def list_models(base_url=DEFAULT_BASE_URL, timeout=DEFAULT_TIMEOUT):
    """List available models from Ollama."""
    try:
        req = HttpRequest.newBuilder() \
            .uri(URI.create("{}/api/tags".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)) \
            .GET().build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        if resp.statusCode() not in range(200, 300):
            raise OllamaException("Ollama returned {}: {}".format(resp.statusCode(), resp.body()))
        body = resp.body()
        models = []
        # Manual parse to avoid json import issues in Jython
        import re
        for m in re.finditer(r'"name"\s*:\s*"([^"]+)"', body):
            models.append(m.group(1))
        return models
    except Exception as e:
        if isinstance(e, OllamaException):
            raise
        raise OllamaException("Failed to list models: {}".format(str(e)))

def chat(model, system_prompt, user_message, base_url=DEFAULT_BASE_URL,
         timeout=DEFAULT_TIMEOUT, num_ctx=None, stream=False, on_chunk=None):
    """
    Send chat request to Ollama.
    If stream=True and on_chunk is provided, calls on_chunk(content) for each token.
    Returns ChatResult on success, raises OllamaException on failure.
    """
    messages = []
    if system_prompt and system_prompt.strip():
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})
    
    body = {"model": model, "messages": messages, "stream": stream}
    if num_ctx:
        body["options"] = {"num_ctx": num_ctx}
    
    json_body = _json_dumps(body)
    try:
        req = HttpRequest.newBuilder() \
            .uri(URI.create("{}/api/chat".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)) \
            .header("Content-Type", "application/json") \
            .POST(HttpRequest.BodyPublishers.ofString(json_body)) \
            .build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        if resp.statusCode() not in range(200, 300):
            raise OllamaException("Ollama returned {}: {}".format(resp.statusCode(), resp.body()))
        
        response_body = resp.body()
        
        if stream and on_chunk:
            # Streaming: parse line-by-line
            for line in response_body.split('\n'):
                line = line.strip()
                if not line:
                    continue
                error = _parse_json_string(line, "error")
                if error:
                    raise OllamaException(error)
                content = _parse_json_string(line, "content")
                if content:
                    on_chunk(content)
            return ChatResult("", None, None)
        else:
            error = _parse_json_string(response_body, "error")
            if error:
                raise OllamaException(error)
            content = _parse_json_string(response_body, "content")
            if content is None:
                # Try extracting from nested message
                import re
                msg_match = re.search(r'"message"\s*:\s*\{[^}]*"content"\s*:\s*"((?:[^"\\]|\\.)*)"', response_body)
                if msg_match:
                    content = msg_match.group(1).replace('\\n', '\n').replace('\\"', '"')
            if content is None:
                raise OllamaException("Empty response from Ollama")
            prompt_tokens = _parse_json_int(response_body, "prompt_eval_count")
            eval_tokens = _parse_json_int(response_body, "eval_count")
            return ChatResult(content, prompt_tokens, eval_tokens)
    except Exception as e:
        if isinstance(e, OllamaException):
            raise
        raise OllamaException("Chat failed: {}".format(str(e)))

# ---- Formatting helpers ----
def format_error(error, base_url, model):
    """Format Ollama error into human-friendly message."""
    msg = str(error)
    if "not found" in msg.lower():
        import re
        m = re.search(r"model\s*['\"]?([^'\"]+)['\"]?", msg, re.IGNORECASE)
        name = m.group(1).strip() if m else model
        return (
            "Model '{}' is not installed.\n\n"
            "Pull it with:\n  ollama pull {}\n\n"
            "Or choose a different model."
        ).format(name, name)
    if any(x in msg.lower() for x in ["connection refused", "connection reset", "no route to host"]):
        return (
            "Cannot connect to Ollama at {}\n\n"
            "  Is Ollama running? Start with: ollama serve\n"
            "  Check the URL in the script configuration."
        ).format(base_url)
    if "timeout" in msg.lower() or "timed out" in msg.lower():
        return "Request timed out. Try a smaller selection or increase timeout."
    return "{}\n\nCheck that Ollama is running at {}".format(msg, base_url)

def security_prompts():
    """Return default security prompts (mirrors Burp SecurityPrompts.kt)."""
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
        return "## Vulnerability Assessment (AI)\n\n{}\n\n---\n*Assessment generated by ZAP Ollama*".format(text.strip())
    return "## AI-Assisted Analysis\n\n{}\n\n---\n*Generated by ZAP Ollama*".format(text.strip())

def truncate(text, max_chars=12000):
    """Truncate text for context window."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... [truncated, {} chars omitted]".format(len(text) - max_chars)

def format_alert(alert):
    """Format a ZAP Alert for AI analysis (mirrors OllamaAuditIssueFormatter)."""
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
    # Markdown code blocks with optional http language
    for m in re.finditer(r'```(?:http)?\s*\n(.*?)```', text, re.DOTALL | re.IGNORECASE):
        block = m.group(1).strip()
        if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', block, re.IGNORECASE):
            results.append(block)
    # Raw HTTP lines
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
