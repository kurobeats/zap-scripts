// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["A file with an interesting extension (script)"]
    const alertDesc = ["A file with an interesting extension was discovered."]
    const alertSolution = "A file with an interesting extension was discovered. It might be nothing, but it's worth investigating."

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

    const interestingext = /(\.(pem|log|pkcs12|p12|pfx|asc|ovpn|cscfg|rdp|mdf|sdf|sqlite|sqlite3|bek|tpm|fve|jks|psafe3|agilekeychain|keychain|pcap|gnucash|kwallet|tblk|plist|xpl|dayone|terraform\.tfvars|exports|functions|extra|asa|inc|zip|tar|gz|tgz|rar|bak|old|tmp|cer|crt|p7b|pkr|skr)\b)/gi

    // Run all regex checks

    matchAndAlert(interestingext, 0)
}
