// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["AWS CLI credentials file Disclosed (script)", "AWS Access Key ID Value Disclosed (script)", "AWS ARN Disclosed (script)", "AWS Secret Access Key Disclosed (script)", "AWS Session Token Disclosed (script)", "AWS credential file Disclosed (script)", "Amazon MWS Auth Token Disclosed (script)", "S3cmd configuration file Disclosed (script)", "Amazon S3 URL Disclosed (script)"]
    const alertDesc = ["An AWS CLI credentials file was discovered.", "An AWS Access Key ID Value was discovered.", "An AWS ARN was discovered.", "An AWS Secret Access Key was discovered.", "An AWS Session Token was discovered.", "An AWS credential file was discovered.", "An Amazon MWS Auth Token was discovered.", "An S3cmd configuration file was discovered.", "An Amazon S3 URL was discovered."]
    const alertSolution = "Ensure API keys, Tokens and configuration files that are publically accessible are not sensitive in nature."

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

    const awsclicreds = /\.?aws\/credentials/g
    const awsaccesskeyid = /((A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}|[A-Z0-9]{20})/g
    const awsarn = /arn:aws:organizations::\d{12}:account\/o-[a-z0-9]{10,32}\/\d{12}/g
    const awssecretskey = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g
    const awssessiontoken = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{16,}(?<![A-Za-z0-9/+=])/g
    const awscredfile = /(aws_access_key_id|aws_secret_access_key)(.{0,20})?=.[0-9a-zA-Z\/+]{20,40}/gi
    const amazonmws = /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g
    const s3cmdconfig = /\.?s3cfg/g
    const amazons3url = /(s3\.amazonaws\.com[\/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com)/g

    // Run all regex checks

    matchAndAlert(awsclicreds, 0)
    matchAndAlert(awsaccesskeyid, 1)
    matchAndAlert(awsarn, 2)
    matchAndAlert(awssecretskey, 3)
    matchAndAlert(awssessiontoken, 4)
    matchAndAlert(awscredfile, 5)
    matchAndAlert(amazonmws, 6)
    matchAndAlert(s3cmdconfig, 7)
    matchAndAlert(amazons3url, 8)
}
