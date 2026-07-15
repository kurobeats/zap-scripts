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

    // ponytail: PEM headers are the anchor — filenames are secondary hints
    // Covers RSA, DSA, ECDSA, Ed25519, ECDSA-SK, Ed25519-SK, XMSS, SSH2, PuTTY, PGP
    const privatesshkey = /(-----BEGIN (EC|RSA|DSA|OPENSSH|SSH2 ENCRYPTED|PGP PRIVATE KEY BLOCK) PRIVATE KEY-----|\bgitlab_rsa\b|\.(pem|ppk|key)\b|\bid_(rsa|dsa|ecdsa[_-]?sk|ed25519[_-]?sk|xmss)\b)/g

    // Run all regex checks

    matchAndAlert(privatesshkey, 0)
}
