// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp

// Cloud platform service tokens & connection strings
// Adapted from secretsifter Patterns.java
function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "HashiCorp Vault Service Token Disclosed (script)",
        "DigitalOcean PAT Disclosed (script)",
        "DigitalOcean OAuth Token Disclosed (script)",
        "Mapbox Access Token Disclosed (script)",
        "Cloudinary API URL Disclosed (script)",
        "Alibaba Cloud Access Key Disclosed (script)",
        "Okta SSWS API Token Disclosed (script)",
        "Azure Storage Connection String Disclosed (script)",
        "Azure IoT Hub Connection String Disclosed (script)",
        "Azure Service Bus Connection String Disclosed (script)",
        "Azure Cosmos DB Connection String Disclosed (script)",
        "Azure Redis Connection String Disclosed (script)",
        "Azure Communication Services Conn String Disclosed (script)"
    ]
    const alertDesc = [
        "A HashiCorp Vault service token (hvs. format) was discovered.",
        "A DigitalOcean personal access token was discovered.",
        "A DigitalOcean OAuth token was discovered.",
        "A Mapbox access token was discovered.",
        "A Cloudinary API URL (contains embedded key+secret) was discovered.",
        "An Alibaba Cloud Access Key ID was discovered.",
        "An Okta SSWS API token was discovered.",
        "An Azure Storage connection string was discovered.",
        "An Azure IoT Hub connection string was discovered.",
        "An Azure Service Bus connection string was discovered.",
        "An Azure Cosmos DB connection string was discovered.",
        "An Azure Redis cache connection string was discovered.",
        "An Azure Communication Services connection string was discovered."
    ]
    const alertSolution = "Ensure cloud credentials and connection strings are not exposed."

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

    const vault = /\bhvs\.[A-Za-z0-9_\-]{90,}\b/g
    const dopat = /\bdop_v1_[a-f0-9]{64}\b/g
    const dooauth = /\bdoo_v1_[a-f0-9]{64}\b/g
    const mapbox = /(?:pk|sk)\.eyJ[A-Za-z0-9_\-]{20,}/g
    const cloudinary = /cloudinary:\/\/[0-9]{6,}:[A-Za-z0-9_\-]{20,}@[a-z][a-z0-9]{1,}/g
    const alibaba = /\bLTAI[A-Za-z0-9]{20}\b/g
    const okta = /\bSSWS\s+[A-Za-z0-9_\-]{40,48}\b/g
    const azstorage = /DefaultEndpointsProtocol=https?;AccountName=[^;]{1,100};AccountKey=[A-Za-z0-9+/=\\]{60,}/gi
    const aziot = /HostName=[^;]{1,100}\.azure-devices\.net[^;]{0,20};SharedAccessKeyName=[^;]{1,100};SharedAccessKey=([A-Za-z0-9+/=\\]{20,200})/gi
    const azsb = /Endpoint=sb:[^;]{0,15}\.servicebus\.windows\.net[^;]{0,30};SharedAccessKeyName=[^;]{1,100};SharedAccessKey=([A-Za-z0-9+/=\\]{20,200})/gi
    const azcosmos = /AccountEndpoint=https?:[^;]{0,15}\.documents\.azure\.com[^;]{0,30};AccountKey=([A-Za-z0-9+/=\\]{20,200})/gi
    const azredis = /[a-zA-Z0-9\-]{1,63}\.redis\.cache\.windows\.net[^,]{0,20},password=([^,\s\"'\r\n]{20,200})/gi
    const azacs = /endpoint=https?:[^;]{0,15}\.communication\.azure\.com[^;]{0,30};accesskey=([A-Za-z0-9+/=\\]{20,200})/gi

    matchAndAlert(vault, 0)
    matchAndAlert(dopat, 1)
    matchAndAlert(dooauth, 2)
    matchAndAlert(mapbox, 3)
    matchAndAlert(cloudinary, 4)
    matchAndAlert(alibaba, 5)
    matchAndAlert(okta, 6)
    matchAndAlert(azstorage, 7)
    matchAndAlert(aziot, 8)
    matchAndAlert(azsb, 9)
    matchAndAlert(azcosmos, 10)
    matchAndAlert(azredis, 11)
    matchAndAlert(azacs, 12)
}
