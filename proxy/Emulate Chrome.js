// Emulate Chrome desktop
// crafted by Anthony Cozamanis, kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36'
	msg.getRequestHeader().setHeader('User-Agent', ua)
	return true
}

function proxyResponse(msg) {
	return true
}
