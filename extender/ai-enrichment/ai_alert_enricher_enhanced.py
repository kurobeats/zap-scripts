# Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

"""
ZAP Script: AI Alert Enricher Enhanced
Type: Alert Filter
Description: Enhanced alert enrichment with auto-triage, CWE mapping, severity review,
             remediation guidance, executive summaries, and exploration suggestions.
             Supports Ollama (local) and OpenRouter (cloud) providers.

Depends on: ai_common.py, ai_common_enhanced.py in same directory.
"""
import sys, os
sys.path.append(os.path.dirname(__file__))

from ai_common import (
    chat, format_alert, format_error, truncate,
    AiConfig, AiException,
    OLLAMA_BASE_URL, OPENROUTER_BASE_URL,
    DEFAULT_SERVICE, DEFAULT_MODEL, DEFAULT_TIMEOUT, DEFAULT_NUM_CTX
)
from ai_common_enhanced import (
    auto_triage, map_cwe, executive_summary, PROMPT_TEMPLATES, MultiModelChat
)
from org.parosproxy.paros.core.scanner import Alert
from org.zaproxy.zap.extension.script import ScriptVars
import threading

# ---- CONFIGURATION ----
def _cfg(key, default):
    try:
        val = ScriptVars.getGlobalVar("ai_alert2.{}".format(key))
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

TRIAGE_MODEL = _cfg("triage_model", MODEL)
REPORT_MODEL = _cfg("report_model", MODEL)

ENABLE_AUTO_TRIAGE = _cfg("auto_triage", "true") == "true"
ENABLE_CWE_MAPPING = _cfg("cwe_mapping", "true") == "true"
ENABLE_REMEDIATION = _cfg("remediation", "true") == "true"
ENABLE_EXPLORE = _cfg("explore", "true") == "true"
ENABLE_EXEC_SUMMARY = _cfg("exec_summary", "false") == "true"

MIN_RISK = _cfg("min_risk", "Low")
MAX_CONCURRENT = int(_cfg("max_concurrent", "3"))

RISK_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
_semaphore = threading.Semaphore(MAX_CONCURRENT)


def _risk_meets_threshold(alert_risk):
    name = alert_risk.name() if hasattr(alert_risk, 'name') else str(alert_risk)
    return RISK_ORDER.get(name, 0) >= RISK_ORDER.get(MIN_RISK, 0)


def _append_to_alert(alert, section_name, content):
    current = alert.getOtherInfo() or ""
    new_info = current
    if new_info:
        new_info += "\n\n"
    new_info += "--- {} (AI) ---\n{}".format(section_name, content.strip())
    alert.setOtherInfo(new_info)


def _build_config(model=None):
    return AiConfig(
        service=SERVICE, base_url=BASE_URL, api_key=API_KEY,
        model=model or MODEL, timeout=TIMEOUT, num_ctx=NUM_CTX
    )


def enrich_alert_enhanced(alert):
    """Enhanced alert enrichment with multiple AI analysis dimensions."""
    if not _risk_meets_threshold(alert.getRisk()):
        return

    def run():
        acquired = _semaphore.acquire(False)
        if not acquired:
            print("[AiEnh] Skipping (concurrency): {}".format(alert.getName()))
            return
        try:
            alert_text = format_alert(alert)
            truncated = truncate(alert_text, 8000)

            # 1. Auto-Triage
            if ENABLE_AUTO_TRIAGE:
                try:
                    cfg = _build_config(TRIAGE_MODEL)
                    triage = auto_triage(truncated, config=cfg)
                    triage_text = (
                        "Verdict: {}\nConfidence: {}\nCWE: {}\nSeverity: {}\n\nReasoning: {}\n\nRemediation: {}"
                    ).format(
                        "REAL vulnerability" if triage.is_real else ("False Positive" if triage.is_real is False else "Uncertain"),
                        triage.confidence, triage.cwe_id or "N/A", triage.severity,
                        triage.reasoning, triage.suggested_remediation
                    )
                    _append_to_alert(alert, "AI Auto-Triage", triage_text)
                    print("[AiEnh] Triage: {} -> {} ({})".format(
                        alert.getName(), "REAL" if triage.is_real else "FP/Uncertain", triage.confidence))
                except Exception as e:
                    _append_to_alert(alert, "AI Auto-Triage", "Error: {}".format(format_error(e, _build_config(TRIAGE_MODEL))))

            # 2. CWE Mapping
            if ENABLE_CWE_MAPPING:
                try:
                    cfg = _build_config()
                    cwe = map_cwe(truncated, config=cfg)
                    cwe_text = "Primary: {} - {}\n".format(cwe["cwe_id"], cwe["cwe_name"])
                    if cwe["alternatives"]:
                        cwe_text += "Alternatives: {}\n".format(", ".join(cwe["alternatives"]))
                    cwe_text += "\n{}".format(cwe["raw"][:300])
                    _append_to_alert(alert, "AI CWE Classification", cwe_text)
                    print("[AiEnh] CWE: {} -> {}".format(alert.getName(), cwe["cwe_id"]))
                except Exception as e:
                    _append_to_alert(alert, "AI CWE Classification", "Error: {}".format(format_error(e, _build_config())))

            # 3. Remediation guidance
            if ENABLE_REMEDIATION:
                try:
                    cfg = _build_config()
                    tmpl = PROMPT_TEMPLATES["remediation_guide"]
                    result = chat(cfg.model, tmpl["system"], truncated, config=cfg)
                    _append_to_alert(alert, "AI Remediation Guidance", result.content)
                    print("[AiEnh] Remediation: {}".format(alert.getName()))
                except Exception as e:
                    _append_to_alert(alert, "AI Remediation", "Error: {}".format(format_error(e, _build_config())))

            # 4. Exploration suggestions
            if ENABLE_EXPLORE:
                try:
                    cfg = _build_config()
                    tmpl = PROMPT_TEMPLATES["explore"]
                    result = chat(cfg.model, tmpl["system"], truncated, config=cfg)
                    _append_to_alert(alert, "AI Exploration Suggestions", result.content)
                    print("[AiEnh] Explore: {}".format(alert.getName()))
                except Exception as e:
                    _append_to_alert(alert, "AI Exploration", "Error: {}".format(format_error(e, _build_config())))

            # 5. Executive summary (High/Critical only)
            if ENABLE_EXEC_SUMMARY and RISK_ORDER.get(alert.getRisk().name(), 0) >= 3:
                try:
                    cfg = _build_config(REPORT_MODEL)
                    summary = executive_summary(truncated, config=cfg)
                    _append_to_alert(alert, "AI Executive Summary", summary)
                    print("[AiEnh] Exec summary: {}".format(alert.getName()))
                except Exception as e:
                    pass

        except Exception as e:
            print("[AiEnh] Error: {}".format(str(e)))
        finally:
            _semaphore.release()

    threading.Thread(target=run, daemon=True).start()


# ---- ZAP Alert Filter hook ----
def applyFilter(alert, source):
    try:
        enrich_alert_enhanced(alert)
    except Exception as e:
        print("[AiEnh] Hook error: {}".format(str(e)))
    return alert


def getName():
    return "AI Alert Enricher Enhanced"


def getDescription():
    return "Enhanced alert enrichment: auto-triage, CWE mapping, remediation, exploration, executive summaries"
