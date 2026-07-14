// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Shell command history file Disclosed (script)", "Shell configuration file Disclosed (script)", "Shell profile configuration file Disclosed (script)", "Shell command alias configuration file Disclosed (script)"]
    const alertDesc = ["A Shell command history file was discovered.", "A Shell configuration file was discovered.", "A Shell profile configuration file was discovered.", "A Shell command alias configuration file was discovered."]
    const alertSolution = "Store Shell files in a secure location."

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

    const shellhistory = /(\.?(bash_|sh_|z)+history)/g
    const shellconfig = /(\.?(bash|zsh|csh)rc)/g
    const shellprofile = /(\.?(bash_)+profile)/g
    const shellalias = /(\.?(bash_)+aliases)/g

    // Run all regex checks

    matchAndAlert(shellhistory, 0)
    matchAndAlert(shellconfig, 1)
    matchAndAlert(shellprofile, 2)
    matchAndAlert(shellalias, 3)
}
