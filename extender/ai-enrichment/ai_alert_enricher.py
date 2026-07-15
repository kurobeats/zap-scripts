# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: AI Alert Enricher
Type: Alert Filter (passive scan rule that enriches alerts with AI analysis)
Description: Enriches ZAP scanner alerts with AI-generated validation, severity assessment,
             and remediation suggestions using Ollama (local) or OpenRouter (cloud).

Depends on: ai_common.py in same directory.

Usage: Configure in ZAP > Scripts > Alert Filter. This script is invoked for each new alert.
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, format_alert, format_error, truncate, security_prompts,
    AiConfig, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL,
    DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from org.parosproxy.paros.core.scanner import Alert
from org.zaproxy.zap.extension.script import ScriptVars
import threading

# ---- CONFIGURATION (override via ScriptVars or edit here) ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ai_alert.{}".format(key))
        return val if val else default
    except:
        return default

SERVICE = _cfg("service", DEFAULT_SERVICE)
API_KEY = _cfg("api_key", "")
BASE_URL = _cfg("base_url", OLLAMA_BASE_URL if SERVICE == "ollama" else OPENROUTER_BASE_URL)
MODEL = _cfg("model", DEFAULT_MODEL)
TIMEOUT = int(_cfg("timeout", str(DEFAULT_TIMEOUT)))
NUM_CTX = int(_cfg("num_ctx", str(DEFAULT_NUM_CTX)))

_ENRICH_CONFIG = AiConfig(
    service=SERVICE, base_url=BASE_URL, api_key=API_KEY,
    model=MODEL, timeout=TIMEOUT, num_ctx=NUM_CTX
)

# Feature flags
ENABLE_FALSE_POSITIVE_CHECK = _cfg("fp_check", "true") == "true"
ENABLE_SEVERITY_REVIEW = _cfg("severity_review", "true") == "true"
ENABLE_REMEDIATION = _cfg("remediation", "true") == "true"
ENABLE_EXPLORE_SUGGESTIONS = _cfg("explore", "true") == "true"

MIN_RISK = _cfg("min_risk", "Low")
MAX_CONCURRENT = int(_cfg("max_concurrent", "3"))

RISK_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
_semaphore = threading.Semaphore(MAX_CONCURRENT)


def _risk_meets_threshold(alert_risk):
    risk_name = alert_risk.name() if hasattr(alert_risk, 'name') else str(alert_risk)
    return RISK_ORDER.get(risk_name, 0) >= RISK_ORDER.get(MIN_RISK, 0)


def _append_to_alert(alert, section_name, content):
    current = alert.getOtherInfo() or ""
    new_info = current
    if new_info:
        new_info += "\n\n"
    new_info += "--- {} (AI) ---\n{}".format(section_name, content.strip())
    alert.setOtherInfo(new_info)


def _enrich_alert(alert, enrichment_type, system_prompt, prefix_label):
    alert_text = format_alert(alert)
    truncated = truncate(alert_text, 8000)
    result = chat(_ENRICH_CONFIG.model, system_prompt, truncated, config=_ENRICH_CONFIG)
    _append_to_alert(alert, prefix_label, result.content)
    print("[AI Enricher] {} for: {}".format(enrichment_type, alert.getName()))


def _check_false_positive(alert):
    prompt = security_prompts()["validate_fp"]
    _enrich_alert(alert, "FP check", prompt, "AI False Positive Assessment")


def _review_severity(alert):
    system_prompt = (
        "You are a security researcher. Review the scanner finding below. "
        "Output: 1) Confirmed severity (Informational/Low/Medium/High/Critical). "
        "2) One-line justification. 3) Any missing context. Be concise."
    )
    _enrich_alert(alert, "Severity review", system_prompt, "AI Severity Review")


def _add_remediation(alert):
    system_prompt = (
        "You are a security engineer. For the vulnerability below, provide: "
        "1) Root cause (1 sentence). 2) Step-by-step remediation. 3) Verification steps. "
        "Be concise and actionable."
    )
    _enrich_alert(alert, "Remediation", system_prompt, "AI Remediation Guidance")


def _add_explore_suggestions(alert):
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
        acquired = _semaphore.acquire(False)
        if not acquired:
            print("[AI Enricher] Skipping (max concurrency): {}".format(alert.getName()))
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
            print("[AI Enricher] Error: {}".format(format_error(e, _ENRICH_CONFIG)))
        finally:
            _semaphore.release()

    threading.Thread(target=run, daemon=True).start()


# ---- ZAP Alert Filter hook ----
def applyFilter(alert, source):
    try:
        enrich_alert(alert)
    except Exception as e:
        print("[AI Enricher] Hook error: {}".format(str(e)))
    return alert


def getName():
    return "AI Alert Enricher"


def getDescription():
    return "Enriches ZAP alerts with AI analysis via Ollama (local) or OpenRouter (cloud)"
