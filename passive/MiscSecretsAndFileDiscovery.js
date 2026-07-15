// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "SSH configuration file Disclosed (script)",
        "Potential cryptographic private key Disclosed (script)",
        "Ruby IRB console history file Disclosed (script)",
        "GNOME Keyring database file Disclosed (script)",
        "Configuration file for auto-login process Disclosed (script)",
        "Rubygems credentials file Disclosed (script)",
        "git-credential-store helper credentials file Disclosed (script)",
        "Git configuration file Disclosed (script)",
        "Chef private key Disclosed (script)",
        "Potential Linux shadow file Disclosed (script)",
        "Potential Linux passwd file Disclosed (script)",
        "Environment configuration file Disclosed (script)",
        "SSH Password Disclosed (script)",
        "Firefox saved password collection Disclosed (script)",
        "KeePass password manager database file Disclosed (script)",
        "URL with Embedded Credentials Disclosed (script)",
        "Database Connection String Disclosed (script)",
        "NPM credentials file Disclosed (script)",
        "PyPI credentials file Disclosed (script)",
        "Docker registry credentials Disclosed (script)",
        "htpasswd file Disclosed (script)",
        "MySQL client config file Disclosed (script)",
        "S3cmd config file Disclosed (script)",
        "AWS CLI credentials file Disclosed (script)",
        "Kubernetes config file Disclosed (script)",
        "GCP service account key Disclosed (script)",
        "Composer auth file Disclosed (script)"
    ]
    const alertDesc = [
        "A SSH configuration file was discovered.",
        "A potential cryptographic private key was discovered.",
        "A Ruby IRB console history file was discovered.",
        "A GNOME Keyring database file was discovered.",
        "A configuration file for auto-login process was discovered.",
        "A Rubygems credentials file was discovered.",
        "A git-credential-store helper credentials file was discovered.",
        "A Git configuration file was discovered.",
        "A Chef private key was discovered.",
        "A potential Linux shadow file was discovered.",
        "A potential Linux passwd file was discovered.",
        "An environment configuration file was discovered.",
        "An SSH password was discovered.",
        "A Firefox saved password collection was discovered.",
        "A KeePass password manager database file was discovered.",
        "A URL containing embedded credentials (user:pass@host) was discovered.",
        "A database connection string containing credentials was discovered.",
        "An NPM credentials file (.npmrc with auth token) was discovered.",
        "A PyPI credentials file (.pypirc) was discovered.",
        "A Docker registry auth config file was discovered.",
        "An htpasswd password file was discovered.",
        "A MySQL client configuration file (.my.cnf) was discovered.",
        "An s3cmd configuration file (.s3cfg) was discovered.",
        "An AWS CLI credentials file was discovered.",
        "A Kubernetes configuration file was discovered.",
        "A GCP service account key file was discovered.",
        "A Composer auth.json file was discovered."
    ]
    const alertSolution = "Ensure configuration files that are publicly accessible are not sensitive in nature."

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

    // ponytail: fixed broken ^/$ patterns (added m flag), added common credential files not in other scripts
    const sshconfig = /(\.?ssh\/config)(?:[^a-zA-Z]|$)/g
    const possprivatekey = /(^key(pair)?$|\.(pem|key|ppk|asc|gpg|pkr|skr)\b)/g
    const rubyirb = /(\.?irb_history)/g
    const gnomekeyring = /key(store|ring)s?/g
    const netrcconfig = /(\.?_?netrc)/g
    const rubygemsconfig = /(\.?gem\/credentials)/g
    const gitcredstorehelper = /(\.?git-credentials)/g
    const gitconfigfile = /(\.?gitconfig)(?:[^a-zA-Z]|$)/g
    const chefprivatekey = /(\.?chef\/.*\.pem)/g
    const linuxshadow = /((\/)?etc\/shadow-?)/g
    const linuxpasswd = /((\/)?etc\/passwd-?)/g
    const envconfigfile = /(\.env(\.\w+)?)/g
    const sshpasswd = /(sshpass -p .{1,100})/g
    const firefoxpasswd = /(\.?mozilla\/firefox\/logins\.json)/g
    const keepassdb = /(\.kdbx?)/g
    const urlcreds = /\bhttps?:\/\/([^\/\s:"'{}]+):([^\/\s@"'{}]+)@([A-Za-z0-9.\-]+)/gi
    const dbconn = /(mongodb(?:\+srv)?|postgresql|postgres|mysql|mssql|sqlserver|redis|rediss|amqp|amqps|jdbc:[a-z]+):\/\/([^\/\s:@]{1,100}):([^\/\s@]{1,200})@([A-Za-z0-9.\-_]{3,})/gi
    const npmrc = /(\.?npmrc)(?:[^a-z]|$)/g
    const pypirc = /(\.?pypirc)/g
    const dockerconfig = /(\.?docker\/config\.json)/g
    const htpasswdfile = /(\.?htpasswd)/g
    const mycnf = /(\.?my\.cnf)/g
    const s3cfg = /(\.?s3cfg)/g
    const awscreds = /(\.aws\/credentials)/g
    const kubeconfig = /(\.?kube\/config)/g
    const gcpkey = /(service-account(?:s)?\.json)/g
    const composerauth = /(composer\.auth\.json)/g

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
    matchAndAlert(npmrc, 17)
    matchAndAlert(pypirc, 18)
    matchAndAlert(dockerconfig, 19)
    matchAndAlert(htpasswdfile, 20)
    matchAndAlert(mycnf, 21)
    matchAndAlert(s3cfg, 22)
    matchAndAlert(awscreds, 23)
    matchAndAlert(kubeconfig, 24)
    matchAndAlert(gcpkey, 25)
    matchAndAlert(composerauth, 26)
}
