"""
ai_common_enhanced.py — Enhanced shared module with advanced features:
  - Multi-model support with model registry
  - Prompt template library
  - Auto-triage mode (classify alerts automatically)
  - Auto-report generation (Markdown/HTML)
  - CWE mapping (AI-inferred CWE IDs)
  - Executive summaries
  - Provider-agnostic (Ollama or OpenRouter via AiConfig)
"""
import json
import time
import threading
from java.net import URI
from java.net.http import HttpClient, HttpRequest, HttpResponse
from java.time import Duration

from ai_common import (
    chat, list_models, health_check, format_error, truncate, extract_http_requests,
    AiConfig, ChatResult, AiException,
    OLLAMA_BASE_URL, DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)

import re as _re

# ---- Enhanced data classes ----
class TriageResult:
    def __init__(self, is_real, confidence, cwe_id, severity, reasoning, suggested_remediation):
        self.is_real = is_real
        self.confidence = confidence
        self.cwe_id = cwe_id
        self.severity = severity
        self.reasoning = reasoning
        self.suggested_remediation = suggested_remediation

# ---- Enhanced: Multi-model support ----
class ModelRegistry:
    def __init__(self, config=None, **kwargs):
        self.config = config or AiConfig(**kwargs)
        self._models = []
        self._by_name = {}

    def refresh(self):
        self._models = list_models(config=self.config)
        self._by_name = {m: m for m in self._models}
        return self._models

    @property
    def models(self):
        return self._models

    def get(self, name):
        return self._by_name.get(name, name)

    def find(self, query):
        q = query.lower()
        return [m for m in self._models if q in m.lower()]

class MultiModelChat:
    """Send same prompt to multiple models (same provider) and compare."""
    def __init__(self, config=None, **kwargs):
        self.config = config or AiConfig(**kwargs)

    def compare(self, models, system_prompt, user_message, num_ctx=None, max_tokens=None):
        results = {}
        errors = {}
        threads = []

        def _worker(model):
            try:
                c = AiConfig(service=self.config.service, base_url=self.config.base_url,
                             api_key=self.config.api_key, model=model,
                             timeout=self.config.timeout, num_ctx=num_ctx or self.config.num_ctx,
                             max_tokens=max_tokens or self.config.max_tokens)
                results[model] = chat(model, system_prompt, user_message, config=c)
            except Exception as e:
                errors[model] = str(e)

        for m in models:
            t = threading.Thread(target=_worker, args=(m,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=self.config.timeout * 2)

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
    return PROMPT_TEMPLATES.get(name)

def list_templates(category=None):
    if category:
        return {k: v for k, v in PROMPT_TEMPLATES.items() if v["category"] == category}
    return dict(PROMPT_TEMPLATES)

# ---- Enhanced: Auto-triage ----
def auto_triage(alert_text, config=None, **kwargs):
    """
    Automatically triage an alert: classify real/false positive, assign CWE, severity.
    Returns TriageResult.
    """
    c = config or AiConfig(**kwargs)
    template = PROMPT_TEMPLATES["auto_triage"]
    result = chat(c.model, template["system"], alert_text, config=c)
    text = result.content.strip()

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

    is_real = None
    if "true" in text.lower() and "false" not in text.lower():
        is_real = True
    elif "false positive" in text.lower():
        is_real = False

    conf = "Medium"
    for c2 in ["High", "Medium", "Low"]:
        if c2.lower() in text.lower():
            conf = c2
            break

    cwe = ""
    cwe_m = _re.search(r'CWE-\d+', text, _re.IGNORECASE)
    if cwe_m:
        cwe = cwe_m.group().upper()

    return TriageResult(is_real, conf, cwe, "Medium", text, "")

# ---- Enhanced: CWE mapping ----
def map_cwe(alert_text, config=None, **kwargs):
    """Map a vulnerability finding to its CWE ID."""
    c = config or AiConfig(**kwargs)
    template = PROMPT_TEMPLATES["cwe_mapper"]
    result = chat(c.model, template["system"], alert_text, config=c)
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
def generate_report(findings, config=None, **kwargs):
    """
    Generate a security report from a list of findings.
    findings: list of dicts with keys: name, severity, url, description, cwe, remediation
    """
    report_format = kwargs.pop('report_format', "markdown")
    c = config or AiConfig(**kwargs)
    template = PROMPT_TEMPLATES["generate_report"]

    findings_text = ""
    for i, f in enumerate(findings):
        findings_text += "### Finding {}: {}\n".format(i + 1, f.get("name", "Unknown"))
        findings_text += "- Severity: {}\n".format(f.get("severity", "N/A"))
        findings_text += "- URL: {}\n".format(f.get("url", "N/A"))
        findings_text += "- CWE: {}\n".format(f.get("cwe", "N/A"))
        findings_text += "- Description: {}\n\n".format(f.get("description", "N/A"))

    result = chat(c.model, template["system"],
                  "Generate a report for the following findings:\n\n{}".format(findings_text),
                  config=c)

    if report_format == "html":
        return _markdown_to_html(result.content)
    return result.content

def _markdown_to_html(md_text):
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
def executive_summary(findings_text, config=None, **kwargs):
    """Generate an executive summary from security findings."""
    c = config or AiConfig(**kwargs)
    template = PROMPT_TEMPLATES["executive_summary"]
    result = chat(c.model, template["system"],
                  "Summarize these security findings:\n\n{}".format(truncate(findings_text, 8000)),
                  config=c)
    return result.content
