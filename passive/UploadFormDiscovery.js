// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["An upload form appeared! (script)"]
    const alertDesc = ["An upload form exists. This isn't an issue, but it could be a lot of fun! Go check it out!."]
    const alertSolution = "This isn't an issue, but it could be a lot of fun!"

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

    const uploadForm = /(type\s*=\s*['"]?file['"]?)/g

    // Run all regex checks

    matchAndAlert(uploadForm, 0)
}
