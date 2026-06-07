"""
ZAP Script: Ollama Alert Enricher
Type: Alert Filter (passive scan rule that enriches alerts with AI analysis)
Description: Enriches ZAP scanner alerts with AI-generated validation, severity assessment,
             and remediation suggestions using local Ollama models.

Place ollama_common.py in the same directory or ZAP's shared scripts folder.

Usage: Configure in ZAP > Scripts > Alert Filter. This script is invoked for each new alert.
Configure the model, base URL, and which enrichments to apply below.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ollama_common import (
    chat, format_alert, format_error, truncate, security_prompts,
    DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX, OllamaException
)
from org.parosproxy.paros.core.scanner import Alert
from org.zaproxy.zap.extension.script import ScriptVars
import threading

# ---- CONFIGURATION (override via ScriptVars or edit here) ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ollama_alert.{}".format(key))
        return val if val else default
    except:
        return default

BASE_URL = _cfg("base_url", DEFAULT_BASE_URL)
MODEL = _cfg("model", DEFAULT_MODEL)
TIMEOUT = int(_cfg("timeout", str(DEFAULT_TIMEOUT)))
NUM_CTX = int(_cfg("num_ctx", str(DEFAULT_NUM_CTX)))

# Which enrichments to apply (edit these to enable/disable)
ENABLE_FALSE_POSITIVE_CHECK = _cfg("fp_check", "true") == "true"
ENABLE_SEVERITY_REVIEW = _cfg("severity_review", "true") == "true"
ENABLE_REMEDIATION = _cfg("remediation", "true") == "true"
ENABLE_EXPLORE_SUGGESTIONS = _cfg("explore", "true") == "true"

# Only process alerts of these risk levels (empty = all)
MIN_RISK = _cfg("min_risk", "Low")  # Low, Medium, High, Informational
MAX_CONCURRENT = int(_cfg("max_concurrent", "3"))

# ---- Risk level ordering ----
RISK_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
_semaphore = threading.Semaphore(MAX_CONCURRENT)


def _risk_meets_threshold(alert_risk):
    """Check if alert risk meets the minimum threshold."""
    risk_name = alert_risk.name() if hasattr(alert_risk, 'name') else str(alert_risk)
    return RISK_ORDER.get(risk_name, 0) >= RISK_ORDER.get(MIN_RISK, 0)


def _enrich_alert(alert, enrichment_type, system_prompt, prefix_label):
    """Send alert to Ollama for enrichment and append result to alert."""
    alert_text = format_alert(alert)
    truncated = truncate(alert_text, 8000)

    result = chat(MODEL, system_prompt, truncated, BASE_URL, TIMEOUT, NUM_CTX,
                  stream=False)

    current = alert.getOtherInfo() or ""
    new_info = current
    if new_info:
        new_info += "\n\n"
    new_info += "--- {} (Ollama AI) ---\n{}".format(prefix_label, result.content.strip())
    alert.setOtherInfo(new_info)

    print("[Ollama Enricher] {} for: {}".format(enrichment_type, alert.getName()))


def _check_false_positive(alert):
    """Validate if alert is a false positive."""
    prompt = security_prompts()["validate_fp"]
    _enrich_alert(alert, "FP check", prompt, "AI False Positive Assessment")


def _review_severity(alert):
    """AI reviews severity classification."""
    system_prompt = (
        "You are a security researcher. Review the scanner finding below. "
        "Output: 1) Confirmed severity (Informational/Low/Medium/High/Critical). "
        "2) One-line justification. 3) Any missing context. Be concise."
    )
    _enrich_alert(alert, "Severity review", system_prompt, "AI Severity Review")


def _add_remediation(alert):
    """AI suggests detailed remediation steps."""
    system_prompt = (
        "You are a security engineer. For the vulnerability below, provide: "
        "1) Root cause (1 sentence). 2) Step-by-step remediation. 3) Verification steps. "
        "Be concise and actionable."
    )
    _enrich_alert(alert, "Remediation", system_prompt, "AI Remediation Guidance")


def _add_explore_suggestions(alert):
    """AI suggests follow-up requests to validate the finding."""
    system_prompt = security_prompts()["explore"]
    _enrich_alert(alert, "Explore", system_prompt, "AI Exploration Suggestions")


def enrich_alert(alert):
    """
    Main entry point — called by ZAP for each new alert raised.
    Runs enrichments in a background thread to avoid blocking the scanner.
    """
    if not _risk_meets_threshold(alert.getRisk()):
        return

    def run():
        acquired = _semaphore.acquire(False)  # non-blocking; skip if too many concurrent
        if not acquired:
            print("[Ollama Enricher] Skipping (max concurrency): {}".format(alert.getName()))
            return
        try:
            if ENABLE_FALSE_POSITIVE_CHECK:
                _check_false_positive(alert)
            if ENABLE_SEVERITY_REVIEW:
                _review_severity(alert)
            if ENABLE_REMEDIATION:
                _add_remediation(alert)
            if ENABLE_EXPLORE_SUGGESTIONS:
                _add_explore_suggestions(alert)
        except Exception as e:
            print("[Ollama Enricher] Error: {}".format(format_error(e, BASE_URL, MODEL)))
        finally:
            _semaphore.release()

    threading.Thread(target=run, daemon=True).start()


# ---- Script hooks for ZAP ----
def applyFilter(alert, source):
    """
    Called by ZAP Alert Filter mechanism.
    Return the (possibly modified) alert. We don't modify it here;
    enrichment is done async via enrich_alert().
    """
    try:
        enrich_alert(alert)
    except Exception as e:
        print("[Ollama Enricher] Hook error: {}".format(str(e)))
    return alert


def getName():
    return "Ollama Alert Enricher"


def getDescription():
    return "Enriches ZAP alerts with AI analysis via local Ollama models"


# ---- Console test helper ----
def test_with_alert():
    """Test enrichment with a sample alert (run from Script Console)."""
    from org.parosproxy.paros.core.scanner import Alert
    from org.parosproxy.paros.network import HttpMessage
    from org.parosproxy.paros.model import Model
    import time

    a = Alert(1, Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, "SQL Injection")
    a.setDescription("Possible SQL injection in the 'id' parameter of GET /search?id=1'")
    a.setSolution("Use parameterized queries")
    a.setUrl("http://example.com/search?id=1%27")

    # Create a mock HTTP message
    msg = HttpMessage()
    req_header = "GET http://example.com/search?id=1%27 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    msg.setRequestHeader(req_header)
    a.setMessage(msg)

    print("Testing Ollama Alert Enricher with sample alert...")
    enrich_alert(a)
    time.sleep(30)  # Wait for async enrichment
    print("Result otherInfo: {}".format(a.getOtherInfo()))


# Run test if executed directly from Script Console
# test_with_alert()
