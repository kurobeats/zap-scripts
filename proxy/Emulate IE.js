// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	const ua = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	return true
}
