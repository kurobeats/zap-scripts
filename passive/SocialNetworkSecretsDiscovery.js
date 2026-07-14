// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Facebook Secret Key Disclosed (script)", "Facebook Client ID Disclosed (script)", "Twitter Secret Key Disclosed (script)", "Twitter Client ID Disclosed (script)", "Twitter Access Token Disclosed (script)", "Twitter OAuth Disclosed (script)", "Linkedin Client ID Disclosed (script)", "LinkedIn Secret Key Disclosed (script)", "Facebook OAuth Disclosed (script)", "Facebook access token Disclosed (script)"]
    const alertDesc = ["A Facebook Secret Key was discovered.", "A Facebook Client ID was discovered.", "A Twitter Secret Key was discovered.", "A Twitter Client ID was discovered.", "A Twitter Access Token was discovered.", "A Twitter OAuth was discovered.", "A Linkedin Client ID was discovered.", "A LinkedIn Secret Key was discovered.", "A Facebook OAuth was discovered.", "A Facebook access token was discovered."]
    const alertSolution = "Ensure tokens and keys that are publically accessible are not sensitive in nature."

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

    const fbsecretkey = /((facebook|fb)(.{0,20})?(\-i)['\"][0-9a-f]{32}['\"])/g
    const fbclientid = /((facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"])/g
    const twsecretkey = /(twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"])/g
    const twclientid = /(twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"])/g
    const twaccesstoken = /([t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40})/g
    const twoauth = /([t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"])/g
    const lkdinclientid = /(linkedin(.{0,20})?(\-i)['\"][0-9a-z]{12}['\"])/g
    const lkdinsecretkey = /(linkedin(.{0,20})?['\"][0-9a-z]{16}['\"])/g
    const fboauth = /([f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"])/g
    const fbaccesstoken = /(EAACEdEose0cBA[0-9A-Za-z]+)/g

    // Run all regex checks

    matchAndAlert(fbsecretkey, 0)
    matchAndAlert(fbclientid, 1)
    matchAndAlert(twsecretkey, 2)
    matchAndAlert(twclientid, 3)
    matchAndAlert(twaccesstoken, 4)
    matchAndAlert(twoauth, 5)
    matchAndAlert(lkdinclientid, 6)
    matchAndAlert(lkdinsecretkey, 7)
    matchAndAlert(fboauth, 8)
    matchAndAlert(fbaccesstoken, 9)
}
