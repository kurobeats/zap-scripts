// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

// Additional vendor API tokens — format-anchored
// Adapted from secretsifter Patterns.java — consolidated catch-all
function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "Discord Bot Token Disclosed (script)",
        "Telegram Bot Token Disclosed (script)",
        "New Relic License Key Disclosed (script)",
        "New Relic Ingest Key Disclosed (script)",
        "Dynatrace API Token Disclosed (script)",
        "PagerDuty API Key Disclosed (script)",
        "Atlassian API Token Disclosed (script)",
        "Contentful CMA Token Disclosed (script)",
        "Doppler Service Token Disclosed (script)",
        "Shopify Access Token Disclosed (script)",
        "HubSpot Private App Token Disclosed (script)",
        "Databricks API Token Disclosed (script)",
        "Airtable PAT Disclosed (script)",
        "Notion Integration Token Disclosed (script)",
        "Dropbox Access Token Disclosed (script)",
        "Figma PAT Disclosed (script)",
        "Postman API Key Disclosed (script)",
        "Rubygems API Token Disclosed (script)",
        "SendinBlue/Brevo API Key Disclosed (script)",
        "Braintree OAuth Token Disclosed (script)",
        "Stripe Webhook Secret Disclosed (script)",
        "Bcrypt Password Hash Disclosed (script)"
    ]
    const alertDesc = [
        "A Discord bot token was discovered.",
        "A Telegram bot API token was discovered.",
        "A New Relic license key was discovered.",
        "A New Relic Insights ingest key was discovered.",
        "A Dynatrace API token was discovered.",
        "A PagerDuty API key was discovered.",
        "An Atlassian API token was discovered.",
        "A Contentful CMA token was discovered.",
        "A Doppler service token was discovered.",
        "A Shopify access token was discovered.",
        "A HubSpot private app token was discovered.",
        "A Databricks API token was discovered.",
        "An Airtable Personal Access Token was discovered.",
        "A Notion integration token was discovered.",
        "A Dropbox access token was discovered.",
        "A Figma Personal Access Token was discovered.",
        "A Postman API key was discovered.",
        "A RubyGems API token was discovered.",
        "A SendinBlue/Brevo API key was discovered.",
        "A Braintree OAuth access token was discovered.",
        "A Stripe webhook signing secret was discovered.",
        "A bcrypt password hash was discovered."
    ]
    const alertSolution = "Ensure vendor tokens and secrets are not exposed."

    function matchAndAlert(re, idx, conf)
    {
        if (conf === undefined) conf = 2
        if (!re.test(body)) return
        re.lastIndex = 0
        const found = []
        let m
        while ((m = re.exec(body)) !== null) found.push(m[0])
        ps.raiseAlert(3, conf, alertTitle[idx], alertDesc[idx], url, '', '', found.toString(), alertSolution, '', 0, 0, msg)
    }

    const discord = /\b(?=\S*[a-z])(?=\S*[0-9])(?:mfa\.[A-Za-z0-9_\-]{20,}|[A-Za-z0-9][A-Za-z0-9_\-]{22,27}\.[A-Za-z0-9_\-]{6,7}\.[A-Za-z0-9_\-]{27})\b/g
    const telegram = /\b[0-9]{8,10}:AA[A-Za-z0-9_\-]{33}\b/g
    const newrelic = /\bNRAK-[A-Z0-9]{27}\b/g
    const newrelicingest = /\bNRII-[A-Za-z0-9_\-]{32}\b/g
    const dynatrace = /\bdt0[a-zA-Z]{2}[0-9]{2}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}\b/g
    const pagerduty = /\b[ru]k\.[A-Za-z0-9_\-]{18}\b/g
    const atlassian = /\b(?:ATATT|ATCTT)[A-Za-z0-9_\-]{100,250}\b/g
    const contentful = /\bCFPAT-[A-Za-z0-9_\-]{43}\b/g
    const doppler = /\bdp\.pt\.[A-Za-z0-9]{43}\b/g
    const shopify = /\bshpat_[a-fA-F0-9]{32}\b/g
    const hubspot = /\bpat-[a-z]{2,3}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g
    const databricks = /\bdapi[a-f0-9]{32}\b/g
    const airtable = /\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b/g
    const notion = /\bsecret_[A-Za-z0-9]{43}\b/g
    const dropbox = /\bsl\.[A-Za-z0-9\-_]{130,}\b/g
    const figma = /\bfigd_[A-Za-z0-9_\-]{43}\b/g
    const postman = /\bPMAK-[a-fA-F0-9]{24}-[A-Za-z0-9]{34}\b/g
    const rubygems = /\brubygems_[a-f0-9]{48}\b/g
    const sendinblue = /\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b/g
    const braintree = /\baccess_token\$(?:production|sandbox)\$[a-f0-9]{16}\$[a-f0-9]{32}\b/g
    const stripewebhook = /\bwhsec_[A-Za-z0-9]{32,40}\b/g
    const bcrypt = /\$2[abxy]\$\d{1,2}\$[./A-Za-z0-9]{53}/g

    matchAndAlert(discord, 0)
    matchAndAlert(telegram, 1)
    matchAndAlert(newrelic, 2)
    matchAndAlert(newrelicingest, 3)
    matchAndAlert(dynatrace, 4)
    matchAndAlert(pagerduty, 5)
    matchAndAlert(atlassian, 6)
    matchAndAlert(contentful, 7)
    matchAndAlert(doppler, 8)
    matchAndAlert(shopify, 9)
    matchAndAlert(hubspot, 10)
    matchAndAlert(databricks, 11)
    matchAndAlert(airtable, 12)
    matchAndAlert(notion, 13)
    matchAndAlert(dropbox, 14)
    matchAndAlert(figma, 15)
    matchAndAlert(postman, 16)
    matchAndAlert(rubygems, 17)
    matchAndAlert(sendinblue, 18)
    matchAndAlert(braintree, 19)
    matchAndAlert(stripewebhook, 20)
    matchAndAlert(bcrypt, 21)
}
