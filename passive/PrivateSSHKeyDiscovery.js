// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Private SSH key Disclosed (script)"]
    const alertDesc = ["A Private SSH key was discovered."]
    const alertSolution = "Store SSH Private keys in a secure location."

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

    const privatesshkey = /(^.*_rsa|^.*_dsa|^.*_ed25519|^.*_ecdsa|-----BEGIN (EC|RSA|DSA|OPENSSH) PRIVATE KEY|PGP)/g

    // Run all regex checks

    matchAndAlert(privatesshkey, 0)
}
