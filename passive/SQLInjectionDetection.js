// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["MySQL error Disclosed (script)", "Postgresql error Disclosed (script)", "MSSQL error Disclosed (script)", "Microsoft Access error Disclosed (script)", "Oracle error Disclosed (script)", "IBM DB2 error Disclosed (script)", "Informix error Disclosed (script)", "Firebird error Disclosed (script)", "SQLite error Disclosed (script)", "SAP DB error Disclosed (script)", "Sybase error Disclosed (script)", "Ingress error Disclosed (script)", "Frontbase error Disclosed (script)", "HSQLDB error Disclosed (script)"]
    const alertDesc = ["A MySQL error was discovered.", "A Postgresql error was discovered.", "A MSSQL error was discovered.", "A Microsoft Access error was discovered.", "An Oracle error was discovered.", "An IBM DB2 error was discovered.", "An Informix error was discovered.", "A Firebird error was discovered.", "An SQLite error was discovered", "A SAP DB error was discovered", "A Sybase error was discovered", "An Ingress error was discovered", "A Frontbase error was discovered", "A HSQLDB error was discovered"]
    const alertSolution = "Ensure proper sanitisation is done on the server side, or don't. I don't care."

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

    const mysql = /(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\.|com\.mysql\.jdbc\.exceptions)/g
    const postgresql = /(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near)/g
    const mssql = /(Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\s\S]Exception.*\WSystem\.Data\.SqlClient\.|[\s\S]Exception.*\WRoadhouse\.Cms\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})/g
    const msaccess = /(Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)/g
    const oracle = /(\bORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*\Woci_.*|Warning.*\Wora_.*)/g
    const ibmdb2 = /(CLI Driver.*DB2|DB2 SQL error|\bdb2_\w+\(|SQLSTATE.+SQLCODE)/g
    const informix = /(Exception.*Informix)/g
    const firebird = /(Dynamic SQL Error|Warning.*ibase_.*)/g
    const sqlite = /(SQLite\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\[SQLITE_ERROR\])/g
    const sapdb = /(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)/g
    const sybase = /(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\.sybase\.jdbc)/g
    const ingress = /(Warning.*ingres_|Ingres SQLSTATE|Ingres\W.*Driver)/g
    const frontbase = /(Exception (condition )?\d+. Transaction rollback.)/g
    const hsqldb = /(org\.hsqldb\.jdbc|Unexpected end of command in statement \[|Unexpected token.*in statement \[)/g

    // Run all regex checks

    matchAndAlert(mysql, 0)
    matchAndAlert(postgresql, 1)
    matchAndAlert(mssql, 2)
    matchAndAlert(msaccess, 3)
    matchAndAlert(oracle, 4)
    matchAndAlert(ibmdb2, 5)
    matchAndAlert(informix, 6)
    matchAndAlert(firebird, 7)
    matchAndAlert(sqlite, 8, 1)
    matchAndAlert(sapdb, 9)
    matchAndAlert(sybase, 10)
    matchAndAlert(ingress, 11)
    matchAndAlert(frontbase, 12)
    matchAndAlert(hsqldb, 13)
}
