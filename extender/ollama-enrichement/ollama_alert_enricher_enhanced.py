"""
ZAP Script: Ollama Alert Enricher Enhanced
Type: Alert Filter
Description: Enhanced alert enrichment with auto-triage, CWE mapping, severity review,
             remediation guidance, executive summaries, and exploration suggestions.
             Uses multi-model support and streaming for real-time enrichment.

Depends on: ollama_common_enhanced.py
"""
import sys, os
sys.path.append(os.path.dirname(__file__))

from ollama_common_enhanced import (
    chat, format_alert, format_error, truncate,
    auto_triage, map_cwe, executive_summary, PROMPT_TEMPLATES, MultiModelChat,
    DEFAULT_BASE_URL, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX, OllamaException
)
from org.parosproxy.paros.core.scanner import Alert
from org.zaproxy.zap.extension.script import ScriptVars
import threading

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ollama_alert2.{}".format(key))
        return val if val else default
    except:
        return default

BASE_URL = _cfg("base_url", DEFAULT_BASE_URL)
MODEL = _cfg("model", DEFAULT_MODEL)
TIMEOUT = int(_cfg("timeout", str(DEFAULT_TIMEOUT)))
NUM_CTX = int(_cfg("num_ctx", str(DEFAULT_NUM_CTX)))

# Triage model (can be different from main model — e.g. use a fast model for triage)
TRIAGE_MODEL = _cfg("triage_model", MODEL)
REPORT_MODEL = _cfg("report_model", MODEL)

# Feature flags
ENABLE_AUTO_TRIAGE = _cfg("auto_triage", "true") == "true"
ENABLE_CWE_MAPPING = _cfg("cwe_mapping", "true") == "true"
ENABLE_REMEDIATION = _cfg("remediation", "true") == "true"
ENABLE_EXPLORE = _cfg("explore", "true") == "true"
ENABLE_EXEC_SUMMARY = _cfg("exec_summary", "false") == "true"

# Risk threshold
MIN_RISK = _cfg("min_risk", "Low")
MAX_CONCURRENT = int(_cfg("max_concurrent", "3"))

RISK_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
_semaphore = threading.Semaphore(MAX_CONCURRENT)


def _risk_meets_threshold(alert_risk):
    name = alert_risk.name() if hasattr(alert_risk, 'name') else str(alert_risk)
    return RISK_ORDER.get(name, 0) >= RISK_ORDER.get(MIN_RISK, 0)


def _append_to_alert(alert, section_name, content):
    """Append AI-generated section to alert's otherInfo."""
    current = alert.getOtherInfo() or ""
    new_info = current
    if new_info:
        new_info += "\n\n"
    new_info += "--- {} (Ollama AI) ---\n{}".format(section_name, content.strip())
    alert.setOtherInfo(new_info)


def enrich_alert_enhanced(alert):
    """Enhanced alert enrichment with multiple AI analysis dimensions."""
    if not _risk_meets_threshold(alert.getRisk()):
        return

    def run():
        acquired = _semaphore.acquire(False)
        if not acquired:
            print("[OllamaEnh] Skipping (concurrency): {}".format(alert.getName()))
            return
        try:
            alert_text = format_alert(alert)
            truncated = truncate(alert_text, 8000)

            # 1. Auto-Triage (classify real/false positive)
            if ENABLE_AUTO_TRIAGE:
                try:
                    triage = auto_triage(truncated, TRIAGE_MODEL, BASE_URL, TIMEOUT, NUM_CTX)
                    triage_text = (
                        "Verdict: {}\nConfidence: {}\nCWE: {}\nSeverity: {}\n\nReasoning: {}\n\nRemediation: {}"
                    ).format(
                        "REAL vulnerability" if triage.is_real else ("False Positive" if triage.is_real is False else "Uncertain"),
                        triage.confidence,
                        triage.cwe_id or "N/A",
                        triage.severity,
                        triage.reasoning,
                        triage.suggested_remediation
                    )
                    _append_to_alert(alert, "AI Auto-Triage", triage_text)
                    print("[OllamaEnh] Triage complete: {} -> {} ({})".format(
                        alert.getName(), "REAL" if triage.is_real else "FP/Uncertain", triage.confidence))
                except Exception as e:
                    _append_to_alert(alert, "AI Auto-Triage", "Error: {}".format(format_error(e, BASE_URL, TRIAGE_MODEL)))

            # 2. CWE Mapping
            if ENABLE_CWE_MAPPING:
                try:
                    cwe = map_cwe(truncated, MODEL, BASE_URL, TIMEOUT, NUM_CTX)
                    cwe_text = "Primary: {} - {}\n".format(cwe["cwe_id"], cwe["cwe_name"])
                    if cwe["alternatives"]:
                        cwe_text += "Alternatives: {}\n".format(", ".join(cwe["alternatives"]))
                    cwe_text += "\n{}".format(cwe["raw"][:300])
                    _append_to_alert(alert, "AI CWE Classification", cwe_text)
                    print("[OllamaEnh] CWE mapped: {} -> {}".format(alert.getName(), cwe["cwe_id"]))
                except Exception as e:
                    _append_to_alert(alert, "AI CWE Classification", "Error: {}".format(format_error(e, BASE_URL, MODEL)))

            # 3. Remediation guidance
            if ENABLE_REMEDIATION:
                try:
                    tmpl = PROMPT_TEMPLATES["remediation_guide"]
                    result = chat(MODEL, tmpl["system"], truncated, BASE_URL, TIMEOUT, NUM_CTX)
                    _append_to_alert(alert, "AI Remediation Guidance", result.content)
                    print("[OllamaEnh] Remediation: {}".format(alert.getName()))
                except Exception as e:
                    _append_to_alert(alert, "AI Remediation", "Error: {}".format(format_error(e, BASE_URL, MODEL)))

            # 4. Exploration suggestions
            if ENABLE_EXPLORE:
                try:
                    tmpl = PROMPT_TEMPLATES["explore"]
                    result = chat(MODEL, tmpl["system"], truncated, BASE_URL, TIMEOUT, NUM_CTX)
                    _append_to_alert(alert, "AI Exploration Suggestions", result.content)
                    print("[OllamaEnh] Explore: {}".format(alert.getName()))
                except Exception as e:
                    _append_to_alert(alert, "AI Exploration", "Error: {}".format(format_error(e, BASE_URL, MODEL)))

            # 5. Executive summary (for High/Critical only by default, to save tokens)
            if ENABLE_EXEC_SUMMARY and _risk_meets_threshold(alert.getRisk()) and RISK_ORDER.get(alert.getRisk().name(), 0) >= 3:
                try:
                    summary = executive_summary(truncated, REPORT_MODEL, BASE_URL, TIMEOUT, NUM_CTX)
                    _append_to_alert(alert, "AI Executive Summary", summary)
                    print("[OllamaEnh] Exec summary: {}".format(alert.getName()))
                except Exception as e:
                    pass

        except Exception as e:
            print("[OllamaEnh] Error: {}".format(str(e)))
        finally:
            _semaphore.release()

    threading.Thread(target=run, daemon=True).start()


# ---- ZAP Alert Filter hook ----
def applyFilter(alert, source):
    try:
        enrich_alert_enhanced(alert)
    except Exception as e:
        print("[OllamaEnh] Hook error: {}".format(str(e)))
    return alert


def getName():
    return "Ollama Alert Enricher Enhanced"


def getDescription():
    return "Enhanced alert enrichment: auto-triage, CWE mapping, remediation, exploration, executive summaries"
