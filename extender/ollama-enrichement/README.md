## Python Scripts

Three self-contained scripts in `zap-scripts/`:

| Script | ZAP Script Type | What it does |
|--------|-----------------|--------------|
| `ollama_common.py` | Shared module | HTTP client — chat, streaming, list models, health check |
| `ask_ollama_standalone.py` | Standalone | Opens a dialog to send arbitrary queries to Ollama |
| `alert_enricher.py` | Alert Filter | Enriches every new alert with AI false-positive assessment and remediation advice |
| `session_helper.py` | HTTP Sender | Monitors traffic for login pages, session cookies, and 401/403 expiry |

### Setup

1. Copy all `.py` files into ZAP's scripts folder
2. In ZAP: **Scripts panel → Load** each script
3. Edit the `OLLAMA_URL` and `MODEL` variables at the top of each script
4. Ensure Ollama is running (`ollama serve`)

## Known Limitations
- Python scripts use Jython 2.7 (no `requests` library — uses `urllib2`)
