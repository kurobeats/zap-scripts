# ZAP-Ollama Scripts

ZAP (Zed Attack Proxy) scripts for AI-powered security testing using local [Ollama](https://ollama.com) models. These scripts mirror the functionality of the Burp-Ollama extension, adapted for OWASP ZAP's scripting engine.

## Architecture

```
zap-scripts/
├── ollama_common.py                    # Shared module (HTTP client, helpers, formatting)
├── ollama_common_enhanced.py           # Enhanced shared module (multi-model, triage, CWE, reports)
│
├── ask_ollama_standalone.py            # [Standalone] AI chat tab
├── ask_ollama_enhanced.py              # [Standalone] Enhanced tab (compare, triage, reports)
│
├── ollama_alert_enricher.py            # [Alert Filter] AI alert enrichment
├── ollama_alert_enricher_enhanced.py   # [Alert Filter] Enhanced enrichment (auto-triage, CWE)
│
├── ollama_session_helper.py            # [Session Mgmt] AI login sequences
└── ollama_session_helper_enhanced.py   # [Session Mgmt] Streaming generation, session validation
```

## Prerequisites

1. **Ollama** installed and running: `ollama serve`
2. At least one model pulled: `ollama pull llama3.2:3b`
3. **OWASP ZAP** ≥ 2.15 with Python scripting support (Jython)

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
| `ask_ollama_standalone.py` | Standalone | Click **+** → **New Script** → select the `.py` file |
| `ask_ollama_enhanced.py` | Standalone | Same as above |
| `ollama_alert_enricher.py` | Alert Filter | **Scripts** tab → right-click Alert Filter scripts → load |
| `ollama_alert_enricher_enhanced.py` | Alert Filter | Same as above |
| `ollama_session_helper.py` | Session Management | **Session Properties** → **Session Management** → select script |
| `ollama_session_helper_enhanced.py` | Session Management | Same as above |

## Configuration

All scripts use `org.zaproxy.zap.extension.script.ScriptVars` for persistence and can be configured via the **Script Console**.

### Common Settings

Set these via the Script Console or by editing defaults in each script:

```python
ScriptVars.setGlobalVar("ollama.base_url", "http://localhost:11434")
ScriptVars.setGlobalVar("ollama.model", "llama3.2:3b")
ScriptVars.setGlobalVar("ollama.timeout", "120")
ScriptVars.setGlobalVar("ollama.num_ctx", "32768")
ScriptVars.setGlobalVar("ollama.streaming", "true")
```

### Alert Enricher Settings

```python
ScriptVars.setGlobalVar("ollama_alert.fp_check", "true")
ScriptVars.setGlobalVar("ollama_alert.severity_review", "true")
ScriptVars.setGlobalVar("ollama_alert.remediation", "true")
ScriptVars.setGlobalVar("ollama_alert.min_risk", "Low")
ScriptVars.setGlobalVar("ollama_alert.max_concurrent", "3")
```

### Enhanced Alert Enricher Settings

```python
ScriptVars.setGlobalVar("ollama_alert2.auto_triage", "true")
ScriptVars.setGlobalVar("ollama_alert2.cwe_mapping", "true")
ScriptVars.setGlobalVar("ollama_alert2.triage_model", "llama3.2:3b")  # fast model for triage
ScriptVars.setGlobalVar("ollama_alert2.report_model", "deepseek-r1:14b")  # heavy model for reports
```

### Session Helper Settings

```python
ScriptVars.setGlobalVar("ollama_session.login_url", "https://example.com/login")
ScriptVars.setGlobalVar("ollama_session.login_description", "POST to /login with username/password form data")
ScriptVars.setGlobalVar("ollama_session.username", "admin")
ScriptVars.setGlobalVar("ollama_session.password", "password123")
ScriptVars.setGlobalVar("ollama_session.login_scope", "https://example.com")

# Enhanced only:
ScriptVars.setGlobalVar("ollama_session2.session_check_interval", "300")  # revalidate every 5min
ScriptVars.setGlobalVar("ollama_session2.stream_generation", "true")
```

---

## Script Reference

### `ask_ollama_standalone.py` (Standalone)

**ZAP tab** for interactive AI chat. Like Burp-Ollama's Suite Tab.

Features:
- Chat with any Ollama model
- Streaming token output
- Multi-turn conversations (follow-up)
- Send extracted HTTP requests to ZAP Request Editor
- Copy to clipboard / Copy as report snippet

Usage: Open **Ask Ollama** tab in ZAP, type a question, press `Ctrl+Enter`.

---

### `ask_ollama_enhanced.py` (Standalone)

**Enhanced** chat tab with 4 sub-tabs:

| Tab | Feature |
|-----|---------|
| **Chat** | Interactive chat with prompt template selector (11 templates) |
| **Compare Models** | Send same prompt to 2+ models, view side-by-side |
| **Auto-Triage** | Classify alerts as real/FP, map CWE, generate executive summaries |
| **Report** | Collect findings and generate Markdown/HTML reports |

Prompt templates: `Explain Content`, `Analyze for Vulns`, `Validate False Positive`, `Auto-Triage`, `Executive Summary`, `Remediation Guide`, `CWE Mapper`, `Explore Issue`, `Generate Report`, `Suggest Fuzzing Payloads`, `Diff Analysis`.

---

### `ollama_alert_enricher.py` (Alert Filter)

Hooks into ZAP's scanner and enriches each alert with AI analysis.

Enrichments (toggle via config):
- **False Positive Check** — AI validates if alert is real
- **Severity Review** — AI reviews risk classification
- **Remediation** — Step-by-step fix guidance
- **Explore Suggestions** — AI suggests follow-up HTTP requests

Results are appended to the alert's **Other Info** field, visible in the Alerts tab.

---

### `ollama_alert_enricher_enhanced.py` (Alert Filter)

Enhanced enrichment with all standard features plus:

- **Auto-Triage** — Structured JSON output: `{is_real, confidence, cwe, severity, reasoning, remediation}`
- **CWE Mapping** — Infers CWE ID + alternative CWEs
- **Executive Summaries** — For High/Critical alerts
- **Multi-model** — Use fast model for triage, heavy model for reports
- **Concurrency control** — Limits parallel Ollama calls to avoid overload

---

### `ollama_session_helper.py` (Session Management)

Handles authentication using AI-generated login sequences.

Workflow:
1. On first request to in-scope URL, generates login request via Ollama
2. Substitutes `{{username}}` and `{{password}}` placeholders
3. Sends login request, extracts `Set-Cookie` headers
4. Injects cookies into all subsequent in-scope requests

Configuration priority:
1. Manual template (`login_request_template`)
2. AI-generated from description (`login_description`)

---

### `ollama_session_helper_enhanced.py` (Session Management)

Enhanced session handling with:

- **Streaming login generation** — Watch AI build the login request in real time
- **Session validation** — Periodically probes a check URL to detect session expiry
- **Auto-reauthentication** — Automatically re-logins when session becomes invalid
- **AI validation** — Uses a lightweight model to validate session responses
- **Separate validation model** — Use a fast model for checks, heavy model for generation

---

## Testing from Script Console

Each script includes test functions you can invoke from ZAP's Script Console:

```python
# Test alert enricher with a sample alert
import ollama_alert_enricher
ollama_alert_enricher.test_with_alert()

# Test session helper login
import ollama_session_helper
ollama_session_helper.test_login()

# Reset session (force re-login)
ollama_session_helper.reset_session()
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `Cannot connect to Ollama` | Ollama not running | Run `ollama serve` |
| `Model 'X' not installed` | Model not pulled | `ollama pull X` |
| Timeout errors | Model too slow for prompt | Increase timeout or use smaller model |
| Script not loading | Wrong script type | Check script type matches (Standalone/Alert Filter/Session) |
| No Jython available | ZAP Python engine missing | Install ZAP Python add-on from Marketplace |
| `ScriptVars` not persisting | Script scope issue | Use `setGlobalVar` / `getGlobalVar` |

## Architecture Notes

- **Burp Montoya API → ZAP API mapping**: See Phase 2 in the parent project analysis
- **No external JSON libraries** — All JSON parsing is manual regex-based for Jython compatibility
- **Thread-safe** — All scripts use threading for async Ollama calls with SwingUtilities.invokeLater for UI
- **Shared module pattern** — `ollama_common.py` and `ollama_common_enhanced.py` avoid code duplication across scripts
