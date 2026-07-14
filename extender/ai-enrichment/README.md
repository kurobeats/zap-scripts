# ZAP AI Enrichment Scripts

ZAP (Zed Attack Proxy) scripts for AI-powered security testing using **Ollama** (local) or **OpenRouter** (cloud). These scripts mirror the functionality of the Burp-Ollama extension, adapted for OWASP ZAP's scripting engine.

## Architecture

```
zap-scripts/extender/ai-enrichment/
├── ai_common.py                    # Shared module (HTTP client, provider abstraction, helpers)
├── ai_common_enhanced.py           # Enhanced shared module (multi-model, triage, CWE, reports)
│
├── ask_ai_standalone.py            # [Standalone] AI chat tab with provider selection
├── ask_ai_enhanced.py              # [Standalone] Enhanced tab (compare, triage, reports)
│
├── ai_alert_enricher.py            # [Alert Filter] AI alert enrichment
├── ai_alert_enricher_enhanced.py   # [Alert Filter] Enhanced enrichment (auto-triage, CWE)
│
├── ai_session_helper.py            # [Session Mgmt] AI login sequences
└── ai_session_helper_enhanced.py   # [Session Mgmt] Streaming generation, session validation
```

## Provider Support

| Provider | Type | API Key | Default Base URL |
|----------|------|---------|------------------|
| **Ollama** | Local | No | `http://localhost:11434` |
| **OpenRouter** | Cloud | Yes | `https://openrouter.ai/api` |

Switch between providers per-session via the UI dropdown or ScriptVars config.

### Prerequisites

**For Ollama:**
1. Install and run: `ollama serve`
2. Pull a model: `ollama pull llama3.2:3b`

**For OpenRouter:**
1. Get an API key from [openrouter.ai/keys](https://openrouter.ai/keys)
2. Ensure internet connectivity

**Both:**
- OWASP ZAP ≥ 2.15 with Python scripting support (Jython)

## Installation

1. Copy all `.py` files to ZAP's script directory:
   ```
   ~/.ZAP/scripts/scripts/
   ```
   Or configure a custom scripts directory in **ZAP > Options > Scripts**.

2. In ZAP, open the **Scripts Console** (or `Ctrl+Shift+S`).

3. Load each script according to its type:

| Script | Type | How to Load |
|--------|------|-------------|
| `ask_ai_standalone.py` | Standalone | Click **+** → **New Script** → select the `.py` file |
| `ask_ai_enhanced.py` | Standalone | Same as above |
| `ai_alert_enricher.py` | Alert Filter | **Scripts** tab → right-click Alert Filter scripts → load |
| `ai_alert_enricher_enhanced.py` | Alert Filter | Same as above |
| `ai_session_helper.py` | Session Management | **Session Properties** → **Session Management** → select script |
| `ai_session_helper_enhanced.py` | Session Management | Same as above |

## Configuration

All scripts use `org.zaproxy.zap.extension.script.ScriptVars` for persistence.

### Common Settings

```python
ScriptVars.setGlobalVar("ai.service", "ollama")           # or "openrouter"
ScriptVars.setGlobalVar("ai.base_url", "http://localhost:11434")
ScriptVars.setGlobalVar("ai.api_key", "sk-or-v1-...")     # only for OpenRouter
ScriptVars.setGlobalVar("ai.model", "llama3.2:3b")
ScriptVars.setGlobalVar("ai.timeout", "120")
ScriptVars.setGlobalVar("ai.num_ctx", "32768")
ScriptVars.setGlobalVar("ai.streaming", "true")
```

### Alert Enricher Settings

```python
ScriptVars.setGlobalVar("ai_alert.service", "ollama")
ScriptVars.setGlobalVar("ai_alert.api_key", "")
ScriptVars.setGlobalVar("ai_alert.fp_check", "true")
ScriptVars.setGlobalVar("ai_alert.severity_review", "true")
ScriptVars.setGlobalVar("ai_alert.remediation", "true")
ScriptVars.setGlobalVar("ai_alert.min_risk", "Low")
ScriptVars.setGlobalVar("ai_alert.max_concurrent", "3")
```

### Enhanced Alert Enricher Settings

```python
ScriptVars.setGlobalVar("ai_alert2.service", "ollama")
ScriptVars.setGlobalVar("ai_alert2.api_key", "")
ScriptVars.setGlobalVar("ai_alert2.auto_triage", "true")
ScriptVars.setGlobalVar("ai_alert2.cwe_mapping", "true")
ScriptVars.setGlobalVar("ai_alert2.triage_model", "llama3.2:3b")
ScriptVars.setGlobalVar("ai_alert2.report_model", "deepseek-r1:14b")
```

### Session Helper Settings

```python
ScriptVars.setGlobalVar("ai_session.service", "ollama")
ScriptVars.setGlobalVar("ai_session.api_key", "")
ScriptVars.setGlobalVar("ai_session.login_url", "https://example.com/login")
ScriptVars.setGlobalVar("ai_session.login_description", "POST to /login with form data")
ScriptVars.setGlobalVar("ai_session.username", "admin")
ScriptVars.setGlobalVar("ai_session.password", "password123")
ScriptVars.setGlobalVar("ai_session.login_scope", "https://example.com")

# Enhanced only:
ScriptVars.setGlobalVar("ai_session2.session_check_interval", "300")
ScriptVars.setGlobalVar("ai_session2.stream_generation", "true")
```

---

## Script Reference

### `ask_ai_standalone.py` (Standalone)

**ZAP tab** for interactive AI chat with provider selection.

Features:
- Service selector: Ollama (local) or OpenRouter (cloud)
- API key field (shown only for OpenRouter)
- Chat with any model from either provider
- Streaming token output
- Multi-turn conversations
- Send extracted HTTP requests to ZAP Request Editor
- Copy to clipboard / Copy as report snippet

Usage: Open **Ask AI** tab in ZAP, select service/key/model, type a question, press `Ctrl+Enter`.

---

### `ask_ai_enhanced.py` (Standalone)

**Enhanced** chat tab with 4 sub-tabs + provider config:

| Tab | Feature |
|-----|---------|
| **Chat** | Interactive chat with prompt template selector (11 templates) + provider config |
| **Compare Models** | Send same prompt to 2+ models, view side-by-side |
| **Auto-Triage** | Classify alerts as real/FP, map CWE, generate executive summaries |
| **Report** | Collect findings and generate Markdown/HTML reports |

11 prompt templates: `Explain Content`, `Analyze for Vulns`, `Validate False Positive`, `Auto-Triage`, `Executive Summary`, `Remediation Guide`, `CWE Mapper`, `Explore Issue`, `Generate Report`, `Fuzzing Payloads`, `Diff Analysis`.

---

### `ai_alert_enricher.py` (Alert Filter)

Hooks into ZAP's scanner and enriches each alert with AI analysis.

Enrichments:
- **False Positive Check** — AI validates if alert is real
- **Severity Review** — AI reviews risk classification
- **Remediation** — Step-by-step fix guidance
- **Explore Suggestions** — AI suggests follow-up HTTP requests

Results appended to the alert's **Other Info** field.

---

### `ai_alert_enricher_enhanced.py` (Alert Filter)

Enhanced enrichment with all standard features plus:

- **Auto-Triage** — Structured JSON output: `{is_real, confidence, cwe, severity, reasoning, remediation}`
- **CWE Mapping** — Infers CWE ID + alternative CWEs
- **Executive Summaries** — For High/Critical alerts
- **Multi-model** — Use fast model for triage, heavy model for reports
- **Provider-aware** — Configurable service, API key, and per-function model overrides

---

### `ai_session_helper.py` (Session Management)

Handles authentication using AI-generated login sequences.

Workflow:
1. On first request to in-scope URL, generates login request via AI
2. Substitutes `{{username}}` and `{{password}}` placeholders
3. Sends login request, extracts `Set-Cookie` headers
4. Injects cookies into all subsequent in-scope requests

---

### `ai_session_helper_enhanced.py` (Session Management)

Enhanced session handling with:

- **Streaming login generation** — Watch AI build the login request in real time
- **Session validation** — Periodically probes a check URL to detect session expiry
- **Auto-reauthentication** — Automatically re-logins when session becomes invalid
- **AI validation** — Uses a lightweight model to validate session responses
- **Provider-agnostic** — Works with Ollama or OpenRouter

---

## Testing from Script Console

```python
# Test alert enricher
import ai_alert_enricher
ai_alert_enricher.test_with_alert()

# Test session helper login
import ai_session_helper
ai_session_helper.test_login()

# Reset session
ai_session_helper.reset_session()
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|------|
| `Cannot connect` | Provider unreachable | Ollama: run `ollama serve`. OpenRouter: check internet |
| `Model not found` | Model not pulled / wrong name | Ollama: `ollama pull <name>`. OpenRouter: check model ID |
| `Unauthorized` | Missing/invalid API key | Check `api_key` config for OpenRouter |
| Timeout errors | Model too slow | Increase timeout or use smaller model |
| Script not loading | Wrong script type | Check script type matches (Standalone/Alert Filter/Session) |
| No Jython | Python engine missing | Install ZAP Python add-on from Marketplace |

## Migration from ollama-enrichement

The old `ollama-enrichement` folder is replaced by `ai-enrichment`. Key changes:
- Provider-agnostic: supports both Ollama and OpenRouter
- New config keys use `ai.*`, `ai_alert.*`, `ai_session.*` prefixes
- Service selection via `service` config field or UI dropdown
- API key field for OpenRouter authentication
- All imports reference `ai_common` instead of `ollama_common`
- Folder name corrected from "enrichement" to "enrichment"
