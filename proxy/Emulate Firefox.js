// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	return true
}
