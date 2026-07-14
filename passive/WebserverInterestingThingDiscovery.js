// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Authorization Bearer Token (script)", "Authorization Basic (script)", "Rails master key Disclosed (script)", "Ruby on rails secrets.yml file Disclosed (script)", "Jetbrains credentials file Disclosed (script)", "PHP configuration file Disclosed (script)", "Apache htpasswd file Disclosed (script)", "Docker configuration file Disclosed (script)", "NPM configuration file Disclosed (script)", "esmtp Configuration Disclosed (script)", "Atom sftp-deployment Config file Disclosed (script)", "Atom remote-sync Config file Disclosed (script)", "WP-Config file Disclosed (script)", "VSCode vscode-sftp file Disclosed (script)", "Docker registry authentication file Disclosed (script)", "SFTP connection configuration file Disclosed (script)"]
    const alertDesc = ["An Authorization Bearer Token was discovered.", "Authorization Basic was discovered.", "A Rails master key was discovered.", "A Ruby on rails secrets.yml file was discovered.", "A Jetbrains credentials file was discovered.", "A PHP configuration file was discovered.", "An Apache htpasswd file was discovered.", "A Docker configuration file was discovered.", "A NPM configuration file was discovered.", "An esmtp Configuration was discovered.", "An Atom sftp-deployment Config file was discovered.", "An Atom remote-sync Config file was discovered.", "A WP-Config file was discovered.", "A VSCode vscode-sftp file was discovered.", "A Docker registry authentication file was discovered.", "An SFTP connection configuration file was discovered."]
    const alertSolution = "There might not be an issue here but it's worth checking out. This script finds a few things."

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

    const authbtoken = /([Bb]earer\s[\d|a-f]{8}-([\d|a-f]{4}-){3}[\d|a-f]{12}|[Bb]earer\s[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+(\.[A-Za-z0-9\-_.+/=]+)?)/g
    const authbasictoken = /([Bb]asic\s[a-zA-Z0-9=:_\+\/\-]+)/g
    const railsmkey = /(ruby\/config\/master\.key)/g
    const rubysfile = /(web\/ruby\/secrets\.yml)/g
    const jbrainsxml = /(\.?idea\/WebServers\.xml)/g
    const phpconfigfile = /(config(\.inc)?\.php)/g
    const htpasswdfile = /(\.?htpasswd)/g
    const dockerconfigfile = /(\.?dockercfg)/g
    const npmconfig = /(\.?npmrc)/g
    const esmtpconfig = /(\.esmtprc)/g
    const atomsftpdeployment = /((deployment-config(\.json)?|\.ftpconfig))/g
    const atomsremotesync = /(\.remote-sync.json)/g
    const wpconfigfile = /(define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?['|\"].{10,120}['|\"]")/g
    const vscodesftpfile = /(\.?vscode\/sftp\.json)/g
    const dockerregistryauth = /(\.?docker\/config\.json)/g
    const sftpconfig = /(sftp-config(\.json)?)/g

    // Run all regex checks

    matchAndAlert(authbtoken, 0)
    matchAndAlert(authbasictoken, 1)
    matchAndAlert(railsmkey, 2)
    matchAndAlert(rubysfile, 3)
    matchAndAlert(jbrainsxml, 4)
    matchAndAlert(phpconfigfile, 5)
    matchAndAlert(htpasswdfile, 6)
    matchAndAlert(dockerconfigfile, 7)
    matchAndAlert(npmconfig, 8, 1)
    matchAndAlert(esmtpconfig, 9)
    matchAndAlert(atomsftpdeployment, 10)
    matchAndAlert(atomsremotesync, 11)
    matchAndAlert(wpconfigfile, 12)
    matchAndAlert(vscodesftpfile, 13)
    matchAndAlert(dockerregistryauth, 14)
    matchAndAlert(sftpconfig, 15)
}
