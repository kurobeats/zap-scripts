// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["MySQL client command history file Disclosed (script)", "PostgreSQL client command history file Disclosed (script)", "PostgreSQL password file Disclosed (script)", "DBeaver SQL database manager configuration file Disclosed (script)", "SQL dump file Disclosed (script)"]
    const alertDesc = ["A MySQL client command history file was discovered.", "A PostgreSQL client command history file was discovered.", "A PostgreSQL password file was discovered.", "DBeaver SQL database manager configuration file was discovered.", "SQL dump file was discovered."]
    const alertSolution = "Ensure configuration files, passwords and backups that are stored securely."

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

    const mysqlhistory = /((\.)?mysql_history)/g
    const postsqlhistory = /((\.)?psql_history)/g
    const postgrespass = /((\.)?pgpass)/g
    const dbeaverconfig = /\.?dbeaver-data-sources(-[0-9]+)?\.xml/g
    const sqldump = /(\.sql(dump)?)/g

    // Run all regex checks

    matchAndAlert(mysqlhistory, 0)
    matchAndAlert(postsqlhistory, 1)
    matchAndAlert(postgrespass, 2)
    matchAndAlert(dbeaverconfig, 3)
    matchAndAlert(sqldump, 4)
}
