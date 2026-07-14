// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Stripe API key Disclosed (script)", "Recon-ng web reconnaissance framework API key database Disclosed (script)", "Generic API Key Disclosed (script)", "Google Cloud API Key Disclosed (script)", "Picatic API key Disclosed (script)", "Twilio API Key Disclosed (script)", "SendGrid API Key Disclosed (script)", "MailGun API Key Disclosed (script)", "MailChimp API Key Disclosed (script)", "NuGet API Key Disclosed (script)", "SonarQube Docs API Key Disclosed (script)", "StackHawk API Key Disclosed (script)", "Twilio Account SID Disclosed (script)", "Twilio App SID Disclosed (script)"]
    const alertDesc = ["A Stripe API key was discovered.", "A Recon-ng web reconnaissance framework API key database was discovered.", "A Generic API Key was discovered.", "A Google Cloud API Key was discovered.", "A Picatic API key was discovered.", "A Twilio API Key was discovered.", "A SendGrid API Key was discovered.", "A MailGun API Key was discovered.", "A MailChimp API Key was discovered.", "A NuGet API Key was discovered.", "A SonarQube Docs API Key was discovered.", "A StackHawk API Key was discovered.", "A Twilio Account SID was discovered.", "A Twilio App SID was discovered."]
    const alertSolution = "Ensure API keys that are publically accessible are not sensitive in nature."

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

    const stripe = /((?:r|p|s)k_(live|test)_[0-9a-zA-Z]{24})/g
    const reconng = /(\.?recon-ng\/keys\.db)/g
    const generic = /([a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"])/g
    const googlecloud = /(AIza[0-9A-Za-z\-_]{35})/g
    const picatic = /(sk_(live|test)_[0-9a-z]{32})/g
    const twilio = /(SK[0-9a-fA-F]{32})/g
    const sendgrid = /(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})/g
    const mailgun = /(key-[0-9a-zA-Z]{32})/g
    const mailchimp = /([0-9a-f]{32}-us[0-9]{12})/g
    const nuget = /(oy2[a-z0-9]{43})/g
    const sonarqube = /(sonar.{0,50}(\"|'|`)?[0-9a-f]{40}(\"|'|`)?)/g
    const stackhawk = /(hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20})/g
    const twilioaccountsid = /(AC[a-zA-Z0-9_\-]{32})/g
    const twilioappsid = /(AP[a-zA-Z0-9_\-]{32})/g

    // Run all regex checks

    matchAndAlert(stripe, 0)
    matchAndAlert(reconng, 1)
    matchAndAlert(generic, 2)
    matchAndAlert(googlecloud, 3)
    matchAndAlert(picatic, 4)
    matchAndAlert(twilio, 5)
    matchAndAlert(sendgrid, 6)
    matchAndAlert(mailgun, 7)
    matchAndAlert(mailchimp, 8, 1)
    matchAndAlert(nuget, 9)
    matchAndAlert(sonarqube, 10)
    matchAndAlert(stackhawk, 11)
    matchAndAlert(twilioaccountsid, 12)
    matchAndAlert(twilioappsid, 13)
}
