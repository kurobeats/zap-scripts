// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "Shell command history file Disclosed (script)",
        "Shell configuration file Disclosed (script)",
        "Shell profile/environment file Disclosed (script)",
        "Shell command alias file Disclosed (script)",
        "Shell login/logout file Disclosed (script)"
    ]
    const alertDesc = [
        "A shell command history file was discovered (bash, sh, zsh, ksh, csh, tcsh, fish, psql, mysql, python, node, redis).",
        "A shell configuration file was discovered (bashrc, zshrc, cshrc, tcshrc, kshrc, fish config, PowerShell profile, .inputrc).",
        "A shell profile or environment initialization file was discovered (.profile, .bash_profile, .zprofile, .zshenv, .env, config.fish).",
        "A shell command alias configuration file was discovered (.bash_aliases, .zsh_aliases, .csh_aliases, .tcsh_aliases, .aliases).",
        "A shell login/logout file was discovered (.zlogin, .zlogout, .bash_login, .bash_logout)."
    ]
    const alertSolution = "Store shell configuration and history files outside the web root."

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

    // ponytail: covers bash, sh, zsh, ksh, csh, tcsh, fish, dash, ash, mksh, powershell
    // plus common REPL histories that reveal cmd execution patterns

    const shellhistory = /(\.[abkzcstf]+\w*_?history|fish_history|_?history\.(txt|log|psv|csv)|\.(mysql|psql|python|node_repl|redis|sqlite)_history)/g
    const shellconfig = /(\.?(bash|zsh|csh|tcsh|ksh|mksh|sh)rc|config\.fish|profile\.ps1|Microsoft\.PowerShell_profile\.ps1|powershell_transcript\.\d+|\.inputrc)/g
    const shellprofile = /(\.?(bash_|z)?profile|\.zshenv|\.env(\.\w+)?|config\.fish|\.?profile)/g
    const shellalias = /(\.?(bash_|zsh_|csh_|tcsh_)?aliases|\.?alias)/g
    const shelllogin = /(\.?(zlogin|zlogout|bash_login|bash_logout))/g

    // Run all regex checks

    matchAndAlert(shellhistory, 0)
    matchAndAlert(shellconfig, 1)
    matchAndAlert(shellprofile, 2)
    matchAndAlert(shellalias, 3)
    matchAndAlert(shelllogin, 4)
}
