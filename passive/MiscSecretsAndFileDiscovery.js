// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["SSH configuration file Disclosed (script)", "Potential cryptographic private key Disclosed (script)", "Ruby IRB console history file Disclosed (script)", "GNOME Keyring database file Disclosed (script)", "Configuration file for auto-login process Disclosed (script)", "Rubygems credentials file Disclosed (script)", "git-credential-store helper credentials file Disclosed (script)", "Git configuration file Disclosed (script)", "Chef private key Disclosed (script)", "Potential Linux shadow file Disclosed (script)", "Potential Linux passwd file Disclosed (script)", "Environment configuration file Disclosed (script)", "SSH Password Disclosed (script)", "Firefox saved password collection Disclosed (script)", "KeePass password manager database file Disclosed (script)", "URL with Embedded Credentials Disclosed (script)", "Database Connection String Disclosed (script)"]
    const alertDesc = ["A SSH configuration file was discovered.", "A Potential cryptographic private key was discovered.", "A Ruby IRB console history file was discovered.", "A GNOME Keyring database file was discovered.", "A Configuration file for auto-login process was discovered.", "A Rubygems credentials file was discovered.", "A git-credential-store helper credentials file was discovered.", "A Git configuration file was discovered.", "A Chef private key was discovered.", "A Potential Linux shadow file was discovered", "A Potential Linux passwd file was discovered", "An Environment configuration file was discovered", "An SSH Password was discovered", "A Firefox saved password collection was discovered", "A KeePass password manager database file was discovered.", "A URL containing embedded credentials (user:pass@host) was discovered.", "A database connection string containing credentials was discovered."]
    const alertSolution = "Ensure configuration files that are publically accessible are not sensitive in nature."

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

    const sshconfig = /(\.?ssh\/config$)/g
    const possprivatekey = /(^key(pair)?$)/g
    const rubyirb = /((\.)?irb_history)/g
    const gnomekeyring = /(key(store|ring)[\W]+)/g
    const netrcconfig = /((\.|_)?netrc)/g
    const rubygemsconfig = /(\.?gem\/credentials)/g
    const gitcredstorehelper = /(\.?git-credentials)/g
    const gitconfigfile = /(\.?gitconfig)/g
    const chefprivatekey = /(\.?chef\/(.*)\.pem)/g
    const linuxshadow = /(etc\/shadow)/g
    const linuxpasswd = /(etc\/passwd)/g
    const envconfigfile = /(\.env)/g
    const sshpasswd = /(sshpass -p .*)/g
    const firefoxpasswd = /(\.?mozilla\/firefox\/logins\.json)/g
    const keepassdb = /(\.kdbx?)/g
    const urlcreds = /\bhttps?:\/\/([^\/\s:"'{}]+):([^\/\s@"'{}]+)@([A-Za-z0-9.\-]+)/gi
    const dbconn = /(mongodb(?:\+srv)?|postgresql|postgres|mysql|mssql|sqlserver|redis|rediss|amqp|amqps|jdbc:[a-z]+):\/\/([^\/\s:@]{1,100}):([^\/\s@]{1,200})@([A-Za-z0-9.\-_]{3,})/gi

    // Run all regex checks

    matchAndAlert(sshconfig, 0)
    matchAndAlert(possprivatekey, 1)
    matchAndAlert(rubyirb, 2)
    matchAndAlert(gnomekeyring, 3)
    matchAndAlert(netrcconfig, 4)
    matchAndAlert(rubygemsconfig, 5)
    matchAndAlert(gitcredstorehelper, 6)
    matchAndAlert(gitconfigfile, 7)
    matchAndAlert(chefprivatekey, 8)
    matchAndAlert(linuxshadow, 9)
    matchAndAlert(linuxpasswd, 10)
    matchAndAlert(envconfigfile, 11)
    matchAndAlert(sshpasswd, 12)
    matchAndAlert(firefoxpasswd, 13)
    matchAndAlert(keepassdb, 14)
    matchAndAlert(urlcreds, 15)
    matchAndAlert(dbconn, 16)
}
