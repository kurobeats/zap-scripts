// Emulate Safari desktop
// crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	const ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	return true
}
