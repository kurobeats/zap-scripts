// Lazily improved by Anthony Cozamanis - kurobeats@yahoo.co.jp
// CreditCard Finder by freakyclown@gmail.com

function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = ["Credit Card Number(s) Disclosed (script)"]
    const alertDesc = ["Credit Card number(s) was discovered."]
    const alertSolution = "why are you showing Credit and debit card numbers?"

    // Skip binary content types that won't contain CC numbers
    const contenttype = msg.getResponseHeader().getHeader("Content-Type")
    const unwantedfiletypes = ['image/png', 'image/jpeg', 'image/gif',
                               'application/x-shockwave-flash', 'application/pdf']
    if (unwantedfiletypes.indexOf("" + contenttype) >= 0) return

    function matchAndAlert(re, idx, conf)
    {
        if (conf === undefined) conf = 2
        if (!re.test(body)) return
        re.lastIndex = 0
        const found = []
        let m
        while ((m = re.exec(body)) !== null) {
            // Validate with Luhn check before adding
            if (luhncheck(m[0]) === 0) found.push(m[0])
        }
        if (found.length === 0) return
        ps.raiseAlert(3, conf, alertTitle[idx], alertDesc[idx], url, '', '',
                      found.toString(), alertSolution, '', 0, 0, msg)
    }

    const re_visa = /(\b4[0-9]{12}(?:[0-9]{3})?\b)/g
    const re_master = /(\b(?:5[1-5][0-9]{14}|2(?:22[1-9]|2[3-9]\d|[3-6]\d{2}|7[0-2]\d|720)\d{12})\b)/g
    const re_amex = /(\b3[47][0-9]{13}\b)/g
    const re_disc = /(\b6(?:011|5[0-9]{2}|4[4-9]\d)[0-9]{12}\b)/g
    const re_diner = /(\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b)/g
    const re_jcb = /(\b(?:2131|1800|35\d{3})\d{11}\b)/g

    const cards = [re_visa, re_master, re_amex, re_disc, re_diner, re_jcb]
    for (let i = 0; i < cards.length; i++) {
        matchAndAlert(cards[i], 0, 2)
    }
}

function luhncheck(value)
{
    // Based on work by DiegoSalazar (https://gist.github.com/DiegoSalazar)
    let nCheck = 0, nDigit = 0, bEven = false
    value = value.replace(/\D/g, "")

    for (let n = value.length - 1; n >= 0; n--) {
        const cDigit = value.charAt(n)
        nDigit = parseInt(cDigit, 10)

        if (bEven) {
            if ((nDigit *= 2) > 9) nDigit -= 9
        }

        nCheck += nDigit
        bEven = !bEven
    }

    return (nCheck % 10)
}
