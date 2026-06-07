"""
ollama_common_enhanced.py — Enhanced shared module with advanced features:
  - Streaming token output via generator pattern
  - Multi-model support with model registry
  - Prompt template library
  - Auto-triage mode (classify alerts automatically)
  - Auto-report generation (Markdown/HTML)
  - CWE mapping (AI-inferred CWE IDs)
  - Executive summaries
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

# ---- Exceptions ----
class OllamaException(Exception):
    pass

# ---- HTTP Client ----
_client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()

def _json_dumps(obj):
    return json.dumps(obj, separators=(',', ':'))

# ---- Manual JSON parsing (avoids Jackson/Gson dependency) ----
import re as _re

def _extract_str(json_str, key):
    m = _re.search(r'"' + _re.escape(key) + r'"\s*:\s*"((?:[^"\\]|\\.)*)"', json_str)
    if m:
        return m.group(1).replace('\\n', '\n').replace('\\"', '"').replace('\\t', '\t')
    return None

def _extract_int(json_str, key):
    m = _re.search(r'"' + _re.escape(key) + r'"\s*:\s*(-?\d+)', json_str)
    return int(m.group(1)) if m else None

# ---- Data classes ----
class ChatResult:
    def __init__(self, content, prompt_tokens=None, eval_tokens=None, model=None):
        self.content = content
        self.prompt_tokens = prompt_tokens
        self.eval_tokens = eval_tokens
        self.model = model

class TriageResult:
    def __init__(self, is_real, confidence, cwe_id, severity, reasoning, suggested_remediation):
        self.is_real = is_real          # True=real vuln, False=false positive, None=uncertain
        self.confidence = confidence    # High/Medium/Low
        self.cwe_id = cwe_id            # e.g. "CWE-89"
        self.severity = severity        # Critical/High/Medium/Low/Info
        self.reasoning = reasoning
        self.suggested_remediation = suggested_remediation

# ---- Core API ----
def health_check(base_url=DEFAULT_BASE_URL, timeout=DEFAULT_TIMEOUT):
    try:
        req = HttpRequest.newBuilder().uri(URI.create("{}/api/tags".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)).GET().build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        return 200 <= resp.statusCode() < 300
    except:
        return False

def list_models(base_url=DEFAULT_BASE_URL, timeout=DEFAULT_TIMEOUT):
    try:
        req = HttpRequest.newBuilder().uri(URI.create("{}/api/tags".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)).GET().build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        if resp.statusCode() not in range(200, 300):
            raise OllamaException("Ollama returned {}: {}".format(resp.statusCode(), resp.body()))
        models = []
        for m in _re.finditer(r'"name"\s*:\s*"([^"]+)"', resp.body()):
            models.append(m.group(1))
        return models
    except Exception as e:
        if isinstance(e, OllamaException): raise
        raise OllamaException("Failed to list models: {}".format(str(e)))

def chat(model, system_prompt, user_message, base_url=DEFAULT_BASE_URL,
         timeout=DEFAULT_TIMEOUT, num_ctx=None, stream=False, on_chunk=None):
    """Send chat request. If stream=True & on_chunk, calls on_chunk(token) per token."""
    messages = []
    if system_prompt and system_prompt.strip():
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_message})
    body = {"model": model, "messages": messages, "stream": stream}
    if num_ctx:
        body["options"] = {"num_ctx": num_ctx}
    json_body = _json_dumps(body)
    try:
        req = HttpRequest.newBuilder().uri(URI.create("{}/api/chat".format(base_url))) \
            .timeout(Duration.ofSeconds(timeout)) \
            .header("Content-Type", "application/json") \
            .POST(HttpRequest.BodyPublishers.ofString(json_body)).build()
        resp = _client.send(req, HttpResponse.BodyHandlers.ofString())
        if resp.statusCode() not in range(200, 300):
            raise OllamaException("Ollama returned {}: {}".format(resp.statusCode(), resp.body()))
        response_body = resp.body()
        if stream and on_chunk:
            for line in response_body.split('\n'):
                line = line.strip()
                if not line: continue
                err = _extract_str(line, "error")
                if err: raise OllamaException(err)
                content = _extract_str(line, "content")
                if content: on_chunk(content)
            return ChatResult("", 0, 0, model)
        else:
            err = _extract_str(response_body, "error")
            if err: raise OllamaException(err)
            content = _extract_str(response_body, "content")
            if content is None:
                m = _re.search(r'"message"\s*:\s*\{[^}]*"content"\s*:\s*"((?:[^"\\]|\\.)*)"', response_body)
                if m: content = m.group(1).replace('\\n', '\n').replace('\\"', '"')
            if content is None: raise OllamaException("Empty response from Ollama")
            return ChatResult(content, _extract_int(response_body, "prompt_eval_count"),
                            _extract_int(response_body, "eval_count"), model)
    except Exception as e:
        if isinstance(e, OllamaException): raise
        raise OllamaException("Chat failed: {}".format(str(e)))

# ---- Enhanced: Multi-model support ----
class ModelRegistry:
    """Registry of available models with metadata."""
    def __init__(self, base_url=DEFAULT_BASE_URL):
        self.base_url = base_url
        self._models = []
        self._by_name = {}

    def refresh(self):
        self._models = list_models(self.base_url)
        self._by_name = {m: m for m in self._models}
        return self._models

    @property
    def models(self):
        return self._models

    def get(self, name):
        return self._by_name.get(name, name)

    def find(self, query):
        """Find models matching a query (e.g. 'code', 'deepseek', 'llama')."""
        q = query.lower()
        return [m for m in self._models if q in m.lower()]

class MultiModelChat:
    """Send the same prompt to multiple models and compare results."""
    def __init__(self, base_url=DEFAULT_BASE_URL, timeout=DEFAULT_TIMEOUT):
        self.base_url = base_url
        self.timeout = timeout

    def compare(self, models, system_prompt, user_message, num_ctx=None):
        """Run prompt against multiple models in parallel. Returns dict[model_name, ChatResult]."""
        results = {}
        errors = {}
        threads = []

        def _worker(model):
            try:
                results[model] = chat(model, system_prompt, user_message,
                                      self.base_url, self.timeout, num_ctx)
            except Exception as e:
                errors[model] = str(e)

        for m in models:
            t = threading.Thread(target=_worker, args=(m,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=self.timeout * 2)

        return results, errors

# ---- Enhanced: Prompt template library ----
PROMPT_TEMPLATES = {
    "explain": {
        "name": "Explain Content",
        "system": "You are a security researcher, security engineer, and hacker. "
                  "Analyze and explain the content. Be concise. Focus only on what is given.",
        "category": "analysis"
    },
    "analyze_vuln": {
        "name": "Analyze for Vulnerabilities",
        "system": "You are a security researcher. Analyze the content for security vulnerabilities. "
                  "For each finding give: 1) Vulnerability type 2) CWE ID 3) Severity 4) Impact. Be concise.",
        "category": "analysis"
    },
    "validate_fp": {
        "name": "Validate False Positive",
        "system": "You are a security researcher. Evaluate if this finding is real or false positive. "
                  "Output exactly:\nVerdict: [Real/False Positive/Uncertain]\n"
                  "Confidence: [High/Medium/Low]\nCWE: [CWE-XXX or N/A]\nReasoning: [1-2 sentences]",
        "category": "triage"
    },
    "auto_triage": {
        "name": "Auto-Triage",
        "system": "You are a security triage specialist. For the alert below, output JSON:\n"
                  '{"is_real": true|false, "confidence": "High|Medium|Low", '
                  '"cwe": "CWE-XXX", "severity": "Critical|High|Medium|Low|Info", '
                  '"reasoning": "...", "remediation": "..."}',
        "category": "triage"
    },
    "executive_summary": {
        "name": "Executive Summary",
        "system": "You are a security consultant writing for management. "
                  "Summarize the findings: 1) Key risks (2-3 bullets) 2) Business impact "
                  "3) Recommended priorities. Be concise, no technical jargon.",
        "category": "reporting"
    },
    "remediation_guide": {
        "name": "Remediation Guide",
        "system": "You are a security engineer. Provide step-by-step remediation: "
                  "1) Root cause 2) Fix (code/config) 3) Verification. Be actionable.",
        "category": "remediation"
    },
    "cwe_mapper": {
        "name": "CWE Mapper",
        "system": "You are a vulnerability classification expert. For the finding below, "
                  "output exactly:\nCWE: CWE-XXX\nCWE Name: ...\nConfidence: High/Medium/Low\n"
                  "Alternative CWEs: CWE-XXX, CWE-XXX",
        "category": "classification"
    },
    "explore": {
        "name": "Explore Issue",
        "system": "You are a penetration tester. Suggest 3-5 follow-up HTTP requests to "
                  "validate or exploit the finding. Output each as:\n"
                  "1) Goal: ...\n```http\nGET /... HTTP/1.1\nHost: ...\n```",
        "category": "exploration"
    },
    "generate_report": {
        "name": "Generate Report",
        "system": "You are a security report writer. Create a professional vulnerability report "
                  "section: 1) Executive Summary 2) Technical Details 3) Risk Rating (CVSS-like) "
                  "4) Proof of Concept 5) Remediation. Use markdown.",
        "category": "reporting"
    },
    "intruder_payloads": {
        "name": "Suggest Fuzzing Payloads",
        "system": "You are a security researcher. Suggest 10-15 fuzzing payloads for the HTTP "
                  "request. One per line, with brief context. No preamble.",
        "category": "fuzzing"
    },
    "diff_analysis": {
        "name": "Diff Analysis",
        "system": "You are a security researcher. Compare two HTTP responses and identify "
                  "security-relevant differences (auth bypass, info disclosure, behavior change).",
        "category": "analysis"
    },
}

def get_template(name):
    """Get a prompt template by name."""
    return PROMPT_TEMPLATES.get(name)

def list_templates(category=None):
    """List all templates, optionally filtered by category."""
    if category:
        return {k: v for k, v in PROMPT_TEMPLATES.items() if v["category"] == category}
    return dict(PROMPT_TEMPLATES)

# ---- Enhanced: Auto-triage mode ----
def auto_triage(alert_text, model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL,
                timeout=DEFAULT_TIMEOUT, num_ctx=None):
    """
    Automatically triage an alert: classify real/false positive, assign CWE, severity.
    Returns TriageResult.
    """
    template = PROMPT_TEMPLATES["auto_triage"]
    result = chat(model, template["system"], alert_text, base_url, timeout, num_ctx)
    text = result.content.strip()

    # Parse JSON from response (may have markdown wrapping)
    m = _re.search(r'\{[\s\S]*\}', text)
    if m:
        try:
            data = json.loads(m.group())
            return TriageResult(
                is_real=data.get("is_real"),
                confidence=data.get("confidence", "Medium"),
                cwe_id=data.get("cwe", ""),
                severity=data.get("severity", "Medium"),
                reasoning=data.get("reasoning", ""),
                suggested_remediation=data.get("remediation", "")
            )
        except:
            pass

    # Fallback: parse text
    is_real = None
    if "true" in text.lower() and "false" not in text.lower():
        is_real = True
    elif "false positive" in text.lower():
        is_real = False

    conf = "Medium"
    for c in ["High", "Medium", "Low"]:
        if c.lower() in text.lower():
            conf = c
            break

    cwe = ""
    cwe_m = _re.search(r'CWE-\d+', text, _re.IGNORECASE)
    if cwe_m:
        cwe = cwe_m.group().upper()

    return TriageResult(is_real, conf, cwe, "Medium", text, "")

# ---- Enhanced: CWE mapping ----
def map_cwe(alert_text, model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL,
            timeout=DEFAULT_TIMEOUT, num_ctx=None):
    """Map a vulnerability finding to its CWE ID."""
    template = PROMPT_TEMPLATES["cwe_mapper"]
    result = chat(model, template["system"], alert_text, base_url, timeout, num_ctx)
    text = result.content.strip()

    cwe_id = ""
    cwe_m = _re.search(r'CWE-\d+', text, _re.IGNORECASE)
    if cwe_m:
        cwe_id = cwe_m.group().upper()

    cwe_name = ""
    name_m = _re.search(r'(?:CWE Name|Name):\s*(.+)', text)
    if name_m:
        cwe_name = name_m.group(1).strip()

    alternatives = []
    alt_m = _re.search(r'(?:Alternative CWEs|Alternatives):\s*(.+)', text)
    if alt_m:
        alternatives = _re.findall(r'CWE-\d+', alt_m.group(1), _re.IGNORECASE)

    return {"cwe_id": cwe_id, "cwe_name": cwe_name, "alternatives": alternatives, "raw": text}

# ---- Enhanced: Auto-report generation ----
def generate_report(findings, model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL,
                    timeout=DEFAULT_TIMEOUT, num_ctx=None, report_format="markdown"):
    """
    Generate a security report from a list of findings.
    findings: list of dicts with keys: name, severity, url, description, cwe, remediation
    report_format: "markdown" or "html"
    """
    template = PROMPT_TEMPLATES["generate_report"]

    # Build findings text
    findings_text = ""
    for i, f in enumerate(findings):
        findings_text += "### Finding {}: {}\n".format(i + 1, f.get("name", "Unknown"))
        findings_text += "- Severity: {}\n".format(f.get("severity", "N/A"))
        findings_text += "- URL: {}\n".format(f.get("url", "N/A"))
        findings_text += "- CWE: {}\n".format(f.get("cwe", "N/A"))
        findings_text += "- Description: {}\n\n".format(f.get("description", "N/A"))

    result = chat(model, template["system"],
                  "Generate a report for the following findings:\n\n{}".format(findings_text),
                  base_url, timeout, num_ctx)

    if report_format == "html":
        return _markdown_to_html(result.content)
    return result.content

def _markdown_to_html(md_text):
    """Simple markdown to HTML conversion."""
    # Very basic conversion — for production, use a proper library
    html = md_text
    html = _re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=_re.MULTILINE)
    html = _re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=_re.MULTILINE)
    html = _re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=_re.MULTILINE)
    html = _re.sub(r'```(\w*)\n(.*?)```', r'<pre><code>\2</code></pre>', html, flags=_re.DOTALL)
    html = _re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
    html = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', html)
    html = _re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=_re.MULTILINE)
    html = _re.sub(r'^(\d+)\. (.+)$', r'<li>\2</li>', html, flags=_re.MULTILINE)
    return "<html><body>\n{}\n</body></html>".format(html)

# ---- Enhanced: Executive summary ----
def executive_summary(findings_text, model=DEFAULT_MODEL, base_url=DEFAULT_BASE_URL,
                      timeout=DEFAULT_TIMEOUT, num_ctx=None):
    """Generate an executive summary from security findings."""
    template = PROMPT_TEMPLATES["executive_summary"]
    result = chat(model, template["system"],
                  "Summarize these security findings:\n\n{}".format(truncate(findings_text, 8000)),
                  base_url, timeout, num_ctx)
    return result.content

# ---- Utility functions ----
def format_error(error, base_url, model):
    msg = str(error)
    if "not found" in msg.lower():
        m = _re.search(r"model\s*['\"]?([^'\"]+)['\"]?", msg, _re.IGNORECASE)
        name = m.group(1).strip() if m else model
        return "Model '{}' is not installed.\n\nPull: ollama pull {}\nOr choose a different model.".format(name, name)
    if any(x in msg.lower() for x in ["connection refused", "connection reset", "no route to host"]):
        return "Cannot connect to Ollama at {}\n\nIs Ollama running? Run: ollama serve".format(base_url)
    if "timeout" in msg.lower():
        return "Request timed out. Try a smaller selection or increase timeout."
    return "{}\n\nCheck Ollama at {}".format(msg, base_url)

def truncate(text, max_chars=12000):
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n\n... [truncated, {} chars omitted]".format(len(text) - max_chars)

def format_alert(alert):
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
        parts.append("\n**Request:**\n{}".format(str(msg.getRequestHeader())[:2000]))
        resp = msg.getResponseHeader()
        if resp:
            parts.append("\n**Response:**\n{}".format(str(resp)[:2000]))
    return "\n".join(parts)

def extract_http_requests(text):
    results = []
    for m in _re.finditer(r'```(?:http)?\s*\n(.*?)```', text, _re.DOTALL | _re.IGNORECASE):
        block = m.group(1).strip()
        if _re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', block, _re.IGNORECASE):
            results.append(block)
    if not results:
        lines = text.split('\n')
        i = 0
        while i < len(lines):
            if _re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', lines[i].strip(), _re.IGNORECASE):
                buf = [lines[i]]
                i += 1
                while i < len(lines) and lines[i].strip():
                    buf.append(lines[i])
                    i += 1
                results.append('\n'.join(buf))
            else:
                i += 1
    return results
