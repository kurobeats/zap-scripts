# zap-scripts

Custom OWASP ZAP scripts for penetration testing — proxy request/response manipulation and passive scanning.

## Directory structure

```
.
├── README.md
├── proxy/     — ZAP proxy scripts (JS + Zest JSON)
├── passive/   — ZAP passive scan scripts (JS)
└── extender/  — ZAP extension scripts (Python)
```

---

## proxy/ — Proxy scripts

Run on every request/response passing through the ZAP proxy. Two formats: JavaScript (`.js`) and Zest (`.zst`).

### .js scripts

| Script | What it does |
|--------|-------------|
| `Drop requests by response code.js` | Drops responses with HTTP 403, 404, 500, 502 |
| `Emulate Android.js` | Sets User-Agent to Android 14 / Chrome 120 (mobile) |
| `Emulate Chrome.js` | Sets User-Agent to Windows Chrome 120 |
| `Emulate Firefox.js` | Sets User-Agent to Windows Firefox 121 |
| `Emulate IE.js` | Sets User-Agent to Internet Explorer 11 |
| `Emulate iOS.js` | Sets User-Agent to iPhone iOS 17.2 Safari |
| `Emulate Safari.js` | Sets User-Agent to Mac Safari 17.2 |

### .zst scripts (Zest JSON)

| Script | What it does |
|--------|-------------|
| `Add spoofed CORS origin.zst` | Injects `Access-Control-Allow-Origin: *` into response headers |
| `Convert HTTPS links to HTTP.zst` | Replaces `https` → `http` in response body |
| `Disable browser XSS protection.zst` | Injects `X-XSS-Protection: 0` into response headers |
| `Hide Referer header.zst` | Strips `Referer` header from outgoing requests |
| `Ignore cookies.zst` | Strips `Set-Cookie` headers from responses |
| `Remove all JavaScript form validation.zst` | Strips `onsubmit` validation attributes from HTML forms |
| `Remove data validation tags in response body.zst` | Sets `data-val="true"` → `data-val="false"` |
| `Remove HSTS headers.zst` | Removes `Strict-Transport-Security` from responses |
| `Remove object tags in response body.zst` | Removes `<object>` tags from HTML |
| `Remove script tags in response body.zst` | Removes `<script>` tags from HTML |
| `Remove secure flag from cookies.zst` | Strips `Secure` flag from `Set-Cookie` headers |
| `Require non-cached response.zst` | Strips `If-None-Match` / `If-Modified-Since` from requests |
| `Require non-compressed responses.zst` | Strips `Accept-Encoding` from requests |
| `Show commented out in response body.zst` | Strips `<!-- -->`, `//`, `display:none` to reveal hidden content |

---

## extender/ — Extension scripts (Python)

AI-powered ZAP extension scripts using Ollama (local) or OpenRouter (cloud).
Supports interactive chat, alert enrichment, session management, and reporting.

### Files

| File / Dir | Type | What it does |
|------------|------|-------------|
| `ai-enrichment/README.md` | — | Full setup, config, troubleshooting guide |
| `ai_common.py` | Shared | HTTP client, provider abstraction (Ollama/OpenRouter), helpers |
| `ai_common_enhanced.py` | Shared | Multi-model support, prompt templates, auto-triage, report builder |
| `ask_ai_standalone.py` | Standalone | Interactive AI chat tab with provider/model selection, streaming |
| `ask_ai_enhanced.py` | Standalone | Enhanced chat: model comparison, auto-triage, CWE mapping, reports |
| `ai_alert_enricher.py` | Alert Filter | Enriches ZAP alerts with FP check, severity review, remediation |
| `ai_alert_enricher_enhanced.py` | Alert Filter | Auto-triage, CWE inference, executive summaries, multi-model |
| `ai_session_helper.py` | Session Mgmt | AI-generated login sequences, cookie extraction, session injection |
| `ai_session_helper_enhanced.py` | Session Mgmt | Streaming login gen, session validation, auto-reauthentication |

### Providers

| Provider | Type | API Key | Default URL |
|----------|------|---------|-------------|
| **Ollama** | Local | No | `http://localhost:11434` |
| **OpenRouter** | Cloud | Yes | `https://openrouter.ai/api` |

Configuration via `ScriptVars` — see `ai-enrichment/README.md` for full details.

---

## passive/ — Passive scan scripts

All scripts use a common `matchAndAlert()` helper. Every regex is format-anchored (unique prefix/pattern) for near-zero false positives unless noted.

### Token discovery (8 files)

| File | Checks | What it finds |
|------|--------|---------------|
| `AITokenDiscovery.js` | 8 | OpenAI (`sk-`), Anthropic (`sk-ant-api`), HuggingFace (`hf_`), Groq (`gsk_`), Replicate (`r8_`), xAI/Grok (`xai-`), DeepSeek (`sk-` + hex) |
| `APIKeyDiscovery.js` | 15 | Stripe, Google Cloud, Twilio, SendGrid, MailGun, MailChimp, NuGet, SonarQube, StackHawk, Picatic, Recon-ng, Twilio Account/App SIDs |
| `CI_CDTokenDiscovery.js` | 15 | GitHub PATs (all 5 formats: `ghp_`,`gho_`,`ghs_`,`ghr_`,`github_pat_`), GitLab, npm, CircleCI, Terraform Cloud, Pulumi, Buildkite, Netlify, Sentry, SonarQube |
| `VendorTokenDiscovery.js` | 22 | Discord bot tokens, Telegram, New Relic, Dynatrace, PagerDuty, Atlassian, Contentful, Doppler, Shopify, HubSpot, Databricks, Airtable, Notion, Dropbox, Figma, Postman, RubyGems, SendinBlue, Braintree, Stripe webhook, bcrypt hashes |
| `CloudServiceTokenDiscovery.js` | 13 | Vault (`hvs.`), DigitalOcean, Mapbox, Cloudinary, Alibaba, Okta, Azure connection strings (Storage, IoT Hub, Service Bus, Cosmos DB, Redis, ACS) |
| `GoogleRelatedDiscovery.js` | 7 | Google OAuth keys, ya29 tokens, GCP service accounts, reCAPTCHA keys, GCP auth tokens, Firebase FCM keys, GCP API keys |
| `AWSRelatedDiscovery.js` | 9 | AWS CLI creds, Access Key IDs, Secret Keys, Session Tokens, ARNs, MWS tokens, S3 URLs, s3cmd config |
| `InfrastructureRelatedDiscovery.js` | 27 | DigitalOcean, GitHub keys, Firebase, Slack tokens/webhooks, IPs, JWT, Artifactory, CodeClimate, Sauce, Heroku, Splunk, Square, PayPal, Instagram, Teams/Discord webhooks, GCP secrets, generic API key headers |

### Discovery by file type (6 files)

| File | Checks | What it finds |
|------|--------|---------------|
| `MiscSecretsAndFileDiscovery.js` | 27 | SSH config, .irb_history, GNOME keyring, .netrc, .git-credentials, .gitconfig, Chef .pem, shadow/passwd, .env, sshpass, Firefox logins, KeePass, URLs with creds, DB connection strings, .npmrc, .pypirc, Docker config, .htpasswd, .my.cnf, .s3cfg, AWS CLI creds, kubeconfig, GCP SA keys, Composer auth |
| `ShellFileDiscovery.js` | 5 | Shell history/config/profile/alias/login files — bash, sh, zsh, ksh, csh, tcsh, fish, dash, ash, mksh, PowerShell + REPL histories (mysql, psql, python, node, redis) |
| `DatabaseRelatedFileDiscovery.js` | 5 | `.mysql_history`, `.psql_history`, `.pgpass`, DBeaver config, SQL dump files |
| `InterestingFileDiscovery.js` | 1 | Files with interesting extensions (.pem, .log, .p12, .pfx, .asc, .ovpn, .rdp, .sqlite, .kdbx, archives, backups, certs) |
| `PrivateSSHKeyDiscovery.js` | 1 | Private SSH keys — PEM headers (`BEGIN * PRIVATE KEY`), key filenames (id_rsa, id_ed25519, id_ecdsa_sk, id_xmss), .pem/.ppk/.key extensions |
| `WebserverInterestingThingDiscovery.js` | 16 | Bearer/Basic auth tokens, Rails master key, secrets.yml, Jetbrains XML, PHP config, .htpasswd, Docker config, .npmrc, WP-config, sftp config |

### Vulnerability detection (2 files)

| File | Checks | What it finds |
|------|--------|---------------|
| `SQLInjectionDetection.js` | 25 | SQL error messages / stack traces — MySQL, PostgreSQL, MSSQL, Access, Oracle, DB2, Informix, Firebird, SQLite, SAP, Sybase, Ingres, Frontbase, HSQLDB, H2, MonetDB, Derby, Vertica, Presto, ClickHouse, CrateDB, Cubrid, Virtuoso, Snowflake, SAP HANA |
| `Find Credit Cards.js` | 6 | Credit card numbers (Visa, Mastercard, Amex, Discover, Diners, JCB) with Luhn validation, skips binary content types |
| `UploadFormDiscovery.js` | 1 | HTML file upload forms (`<input type="file">`) |

---

## Notes

- All passive scripts use `matchAndAlert(re, idx, conf)` helper — extracts all matches, raises single ZAP alert
- Confidence: `conf=1` (low) for broad/high-FP patterns, `conf=2` (medium) for format-anchored tokens
- Zest `.zst` files are plain JSON, not zstd-compressed
- All scripts carry attribution: `// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp`
- Patterns sourced from [secretsifter Patterns.java](https://github.com/nahamsec/secretsifter) and [sqlmap errors.xml](https://github.com/sqlmapproject/sqlmap)
