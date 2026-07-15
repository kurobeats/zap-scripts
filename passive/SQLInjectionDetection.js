// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "MySQL error Disclosed (script)", "Postgresql error Disclosed (script)",
        "MSSQL error Disclosed (script)", "Microsoft Access error Disclosed (script)",
        "Oracle error Disclosed (script)", "IBM DB2 error Disclosed (script)",
        "Informix error Disclosed (script)", "Firebird error Disclosed (script)",
        "SQLite error Disclosed (script)", "SAP MaxDB error Disclosed (script)",
        "Sybase error Disclosed (script)", "Ingres error Disclosed (script)",
        "Frontbase error Disclosed (script)", "HSQLDB error Disclosed (script)",
        "H2 error Disclosed (script)", "MonetDB error Disclosed (script)",
        "Apache Derby error Disclosed (script)", "Vertica error Disclosed (script)",
        "Presto error Disclosed (script)", "ClickHouse error Disclosed (script)",
        "CrateDB error Disclosed (script)", "Cubrid error Disclosed (script)",
        "Virtuoso error Disclosed (script)", "Snowflake error Disclosed (script)",
        "SAP HANA error Disclosed (script)"
    ]
    const alertDesc = [
        "A MySQL error was discovered.", "A Postgresql error was discovered.",
        "A MSSQL error was discovered.", "A Microsoft Access error was discovered.",
        "An Oracle error was discovered.", "An IBM DB2 error was discovered.",
        "An Informix error was discovered.", "A Firebird error was discovered.",
        "An SQLite error was discovered.", "A SAP MaxDB error was discovered.",
        "A Sybase error was discovered.", "An Ingres error was discovered.",
        "A Frontbase error was discovered.", "A HSQLDB error was discovered.",
        "An H2 error was discovered.", "A MonetDB error was discovered.",
        "An Apache Derby error was discovered.", "A Vertica error was discovered.",
        "A Presto error was discovered.", "A ClickHouse error was discovered.",
        "A CrateDB error was discovered.", "A Cubrid error was discovered.",
        "A Virtuoso error was discovered.", "A Snowflake error was discovered.",
        "A SAP HANA error was discovered."
    ]
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

    // ponytail: patterns from sqlmap errors.xml — covers error-based detection for 25 DBMS

    const mysql = /(SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that (corresponds to|fits) your (MySQL|MariaDB|Drizzle|TiDB) server version|Unknown column '[^']+' in 'field list'|MySqlClient\.|com\.mysql\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[.\/_\\]Mysql|MySqlException|pymysql\.err\.|MySQLdb\.(_exceptions\.|\w+Error))/g
    const postgresql = /(PostgreSQL.*?ERROR|Warning.*?\Wpg_|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s+syntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\.postgresql\.jdbc|Pdo[.\/_\\]Pgsql|PSQLException|psycopg2?\.(errors\.|\w+Error)|asyncpg\.(exceptions\.|\w+Error))/g
    const mssql = /(Driver.*? SQL[\-\_\ ]*Server|OLE DB.*? SQL Server|\bSQL Server[^<"]+Driver|Warning.*?\W(mssql|sqlsrv)_|\bSQL Server[^<"]+[0-9a-fA-F]{8}|[\s\S]Exception.*?\bRoadhouse\.Cms\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|System\.Data\.SqlClient\.(SqlException|SqlConnection\.OnError)|\[SQL Server\]|ODBC SQL Server Driver|ODBC Driver \d+ for SQL Server|SQLServer JDBC Driver|com\.jnetdirect\.jsql|macromedia\.jdbc\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\.microsoft\.sqlserver\.jdbc|Pdo[.\/_\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|Unclosed quotation mark after the character string)/g
    const msaccess = /(Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \(missing operator\) in query expression)/g
    const oracle = /(\bORA-\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\.jdbc\.oracle|oracle\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[.\/_\\](Oracle|OCI)|OracleException|cx_Oracle\.\w+Error|oracledb\.(exceptions\.|\w+Error))/g
    const ibmdb2 = /(CLI Driver.*?DB2|DB2 SQL error|\bdb2_\w+\(|SQLCODE[=:\d, -]+SQLSTATE|com\.ibm\.db2\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[.\/_\\]Ibm|DB2Exception|ibm_db_dbi\.ProgrammingError)/g
    const informix = /(Warning.*?\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\.informix\.jdbc|weblogic\.jdbc\.informix|Pdo[.\/_\\]Informix|IfxException)/g
    const firebird = /(Dynamic SQL Error.{1,10}SQL error code|Warning.*?\Wibase_|org\.firebirdsql\.jdbc|Pdo[.\/_\\]Firebird)/g
    const sqlite = /(SQLite\/JDBCDriver|SQLite\.Exception|(Microsoft|System)\.Data\.SQLite\.SQLiteException|Warning.*?\W(sqlite_|SQLite3::)|\[SQLITE_ERROR\]|SQLite error \d+:|sqlite3\.OperationalError:|SQLite3::SQLException|org\.sqlite\.JDBC|Pdo[.\/_\\]Sqlite|SQLiteException|SqliteError:)/g
    const sapdb = /(SQL error.*?POS([0-9]+)|Warning.*?\Wmaxdb_|DriverSapDB|-3014.*?Invalid end of SQL statement|com\.sap\.db(tech)?\.jdbc|\[-3008\].*?: Invalid keyword or missing delimiter)/g
    const sybase = /(Warning.*?\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\.Data\.AseClient|com\.sybase\.jdbc)/g
    const ingres = /(Warning.*?\Wingres_|Ingres SQLSTATE|Ingres\W.*?Driver|com\.ingres\.gcf\.jdbc)/g
    const frontbase = /(Exception (condition )?\d+\. Transaction rollback|com\.frontbase\.jdbc|Syntax error 1\. Missing|(Semantic|Syntax) error [1-4]\d{2}\.)/g
    const hsqldb = /(org\.hsqldb\.jdbc|Unexpected end of command in statement \[|Unexpected token.*?in statement \[)/g
    const h2 = /(org\.h2\.jdbc|\[42000-\d+\])/g
    const monetdb = /(![0-9]{5}![^\n]+(failed|unexpected|error|syntax|expected|violation|exception)|\[MonetDB\]\[ODBC Driver|nl\.cwi\.monetdb\.jdbc|org\.monetdb\.jdbc)/g
    const derby = /(Syntax error: Encountered|org\.apache\.derby|ERROR 42X01)/g
    const vertica = /(, Sqlstate: (3F|42).{3}, (Routine|Hint|Position):|\/vertica\/Parser\/scan|com\.vertica\.jdbc|org\.jkiss\.dbeaver\.ext\.vertica|com\.vertica\.dsi\.dataengine)/g
    const presto = /(com\.facebook\.presto\.jdbc|io\.prestosql\.jdbc|com\.simba\.presto\.jdbc|UNION query has different number of fields: \d+, \d+|line \d+:\d+: mismatched input '[^']+'. Expecting:)/g
    const clickhouse = /(Code: \d+[., ]+DB::Exception:|Syntax error: failed at position \d+)/g
    const cratedb = /(io\.crate\.)/g
    const cubrid = /(\[CAS INFO|cubrid\.jdbc\.driver)/g
    const virtuoso = /(SQ074: Line \d+:|SR185: Undefined procedure|SQ200: No table |Virtuoso S0002 Error|\[(Virtuoso Driver|Virtuoso iODBC Driver)\]\[Virtuoso Server\])/g
    const snowflake = /(001003 \(42000\):|100038 \(22018\):|000904 \(42000\):|SQL compilation error: (syntax )?error line \d+ at position \d+)/g
    const saphana = /(SAP DBTech JDBC|invalid number: not a valid number string|sql syntax error:.*?\(at pos \d+\)|inserted value too large for column)/g

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
    matchAndAlert(ingres, 11)
    matchAndAlert(frontbase, 12)
    matchAndAlert(hsqldb, 13)
    matchAndAlert(h2, 14)
    matchAndAlert(monetdb, 15)
    matchAndAlert(derby, 16)
    matchAndAlert(vertica, 17)
    matchAndAlert(presto, 18)
    matchAndAlert(clickhouse, 19)
    matchAndAlert(cratedb, 20)
    matchAndAlert(cubrid, 21)
    matchAndAlert(virtuoso, 22)
    matchAndAlert(snowflake, 23)
    matchAndAlert(saphana, 24)
}
