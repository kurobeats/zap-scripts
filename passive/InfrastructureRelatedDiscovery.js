// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["DigitalOcean doctl command-line client configuration file Disclosed (script)", "Tugboat DigitalOcean management tool configuration Disclosed (script)", "GitHub Hub command-line client configuration file Disclosed (script)", "Firebase URL Disclosed (script)", "GitHub stuff Disclosed (script)", "Generic Secret Disclosed (script)", "IP Address Disclosed (script)", "Slack Token Disclosed (script)", "Slack Webhook Disclosed (script)", "Outlook Team Webhook Disclosed (script)", "Artifactory stuff Disclosed (script)", "CodeClimate stuff Disclosed (script)", "Sauce Token Disclosed (script)", "Github Key Disclosed (script)", "Heroku Key Disclosed (script)", "Splunk Authorization Disclosed (script)", "Square Access Token Disclosed (script)", "Square OAuth Secret Disclosed (script)", "PayPal/Braintree Access Token Disclosed (script)", "Instagram Access Token Disclosed (script)", "GitHub Access Token in URL Disclosed (script)", "JSON Web Token Disclosed (script)", "Microsoft Teams Webhook URL Disclosed (script)", "GCP OAuth2 Client Secret Disclosed (script)", "GCP Service Account Email Disclosed (script)", "Discord Webhook URL Disclosed (script)", "Generic API Key in Header Disclosed (script)"]
    const alertDesc = ["A DigitalOcean doctl command-line client configuration file was discovered.", "A Tugboat DigitalOcean management tool configuration was discovered.", "A GitHub Hub command-line client configuration file was discovered.", "A Firebase URL was discovered.", "GitHub stuff was discovered.", "A Generic Secret was discovered.", "An IP Address was discovered.", "A Slack Token was discovered.", "A Slack Webhook was discovered.", "An Outlook Team Webhook was discovered.", "Artifactory stuff was discovered", "CodeClimate stuff was discovered", "A Sauce Token was discovered", "A Github Key was discovered", "A Heroku Key was discovered", "Splunk Authorization was discovered", "A Square Access Token was discovered", "A Square OAuth Secret was discovered", "A PayPal/Braintree Access Token was discovered", "An Instagram access token was discovered.", "A GitHub access token in a URL was discovered.", "A JSON Web Token was discovered.", "A Microsoft Teams webhook URL was discovered.", "A GCP OAuth2 client secret was discovered.", "A GCP service account email was discovered.", "A Discord webhook URL was discovered.", "A generic API key reference (api[key...]) was discovered."]
    const alertSolution = "Ensure API keys, Tokens and configuration files that are publically accessible are not sensitive in nature."

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

    const doctlcliconfig = /(doctl\/config\.yaml)/g
    const dotugboat = /(\.?tugboat)/g
    const githubhub = /(config\/hub)/g
    const firebaseurl = /([a-z0-9.-]+\.firebaseio\.com)/g
    const githubstuff = /([g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"])/g
    const genericsecret = /([s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"])/g
    const ipaddress = /([^\.0-9](([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])[^\.0-9])/g
    const slacktoken = /((xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}))/g
    const slackwebhook = /(https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24})/g
    const outlookwebhook = /(https:\/\/outlook\.office\.com\/webhook\/[0-9a-f-]{36}@)/g
    const artifactorystuff = /(artifactory.{0,50}(\"|'|`)?[a-zA-Z0-9=]{112}(\"|'|`)?)/g
    const codeclimatestuff = /(codeclima.{0,50}(\"|'|`)?[0-9a-f]{64}(\"|'|`)?)/g
    const saucetoken = /(sauce.{0,50}(\"|'|`)?[0-9a-f-]{36}(\"|'|`)?)/g
    const githubkey = /(github(.{0,20})?(\-i)['\"][0-9a-zA-Z]{35,40}['\"])/g
    const herokukey = /(heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"])/g
    const splunkauth = /(Splunk\s(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1})/g
    const squareaccesstoken = /(sq0atp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60})/g
    const squareoauthsecret = /(sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43})/g
    const paypalaccesstoken = /(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})/g
    const instagramtoken = /([0-9a-fA-F]{7}\.[0-9a-fA-F]{32})/g
    const githubaccesstokenurl = /([a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com)/g
    const jsonwebtoken = /(ey[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*\.[A-Za-z0-9._\/-]*|ey[A-Za-z0-9_\/+-]*\.[A-Za-z0-9._\/+-]*)/g
    const teamswh = /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[A-Za-z0-9\-@/]{20,}/g
    const gcpclientsecret = /\bGOCSPX-[A-Za-z0-9_\-]{28}\b/g
    const gcpsaemail = /\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b/g
    const discordwh = /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]{17,19}\/[A-Za-z0-9_\-]{60,68}/g
    const genericapikey = /(api[key|\s*]+[a-zA-Z0-9_\-]+)/g

    // Run all regex checks

    matchAndAlert(doctlcliconfig, 0)
    matchAndAlert(dotugboat, 1)
    matchAndAlert(githubhub, 2)
    matchAndAlert(firebaseurl, 3)
    matchAndAlert(githubstuff, 4)
    matchAndAlert(genericsecret, 5)
    matchAndAlert(ipaddress, 6)
    matchAndAlert(slacktoken, 7)
    matchAndAlert(slackwebhook, 8)
    matchAndAlert(outlookwebhook, 9)
    matchAndAlert(artifactorystuff, 10)
    matchAndAlert(codeclimatestuff, 11)
    matchAndAlert(saucetoken, 12)
    matchAndAlert(githubkey, 13)
    matchAndAlert(herokukey, 14)
    matchAndAlert(splunkauth, 15)
    matchAndAlert(squareaccesstoken, 16)
    matchAndAlert(squareoauthsecret, 17)
    matchAndAlert(paypalaccesstoken, 18)
    matchAndAlert(instagramtoken, 19, 1)
    matchAndAlert(githubaccesstokenurl, 20, 1)
    matchAndAlert(jsonwebtoken, 21)
    matchAndAlert(teamswh, 22)
    matchAndAlert(gcpclientsecret, 23)
    matchAndAlert(gcpsaemail, 24, 1)
    matchAndAlert(discordwh, 25)
    matchAndAlert(genericapikey, 26, 1)
}
