// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Google OAuth Key Disclosed (script)", "Google OAuth Access Token Disclosed (script)", "Google (GCM) Service account Disclosed (script)", "Google reCAPTCHA Key Disclosed (script)", "Google Cloud Platform Auth Token Disclosed (script)", "Firebase Cloud Messaging Key Disclosed (script)", "Google Cloud Platform API Key Disclosed (script)"]
    const alertDesc = ["A Google OAuth Key was discovered.", "A Google OAuth Access Token was discovered.", "A Google (GCM) Service account was discovered.", "A Google reCAPTCHA key was discovered.", "A Google Cloud Platform auth token was discovered.", "A Firebase Cloud Messaging server key was discovered.", "A Google Cloud Platform API key was discovered."]
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

    const googleoauthkey = /([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)/g
    const googleoauthaccesstoken = /(ya29\.[0-9A-Za-z\\-_]+)/g
    const googleserviceaccount = /(((\"|'|`)?type(\"|'|`)?\s{0,50}(:|=>|=)\s{0,50}(\"|'|`)?service_account(\"|'|`)?,?))/g
    const googlerecaptcha = /(6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39})/g
    const gcpauthtoken = /([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/g
    const firebasefcm = /(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})/g
    const gcpapikey = /([A-Za-z0-9_]{21}--[A-Za-z0-9_]{8})/g

    // Run all regex checks

    matchAndAlert(googleoauthkey, 0)
    matchAndAlert(googleoauthaccesstoken, 1)
    matchAndAlert(googleserviceaccount, 2)
    matchAndAlert(googlerecaptcha, 3)
    matchAndAlert(gcpauthtoken, 4, 1)
    matchAndAlert(firebasefcm, 5)
    matchAndAlert(gcpapikey, 6)
}
