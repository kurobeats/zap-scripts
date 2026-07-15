// Lazily crafted by Anthony Cozamanis - kurobeats@yahoo.co.jp
function proxyRequest(msg) {
	return true
}

function proxyResponse(msg) {
	const code = msg.getResponseHeader().getStatusCode()
	if (code == 404 || code == 403 || code == 500 || code == 502) {
		return false
	}
	return true
}
