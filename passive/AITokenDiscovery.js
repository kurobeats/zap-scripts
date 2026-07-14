// AI/ML platform API tokens — format-anchored, near-zero FP
// Adapted from secretsifter Patterns.java
function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "OpenAI API Key Disclosed (script)",
        "OpenAI Project API Key Disclosed (script)",
        "Anthropic API Key Disclosed (script)",
        "Hugging Face API Token Disclosed (script)",
        "Groq API Key Disclosed (script)",
        "Replicate API Token Disclosed (script)",
        "xAI / Grok API Key Disclosed (script)",
        "DeepSeek API Key Disclosed (script)"
    ]
    const alertDesc = [
        "An OpenAI API key (sk-... format) was discovered.",
        "An OpenAI Project API key (sk-proj-... format) was discovered.",
        "An Anthropic API key (sk-ant-api... format) was discovered.",
        "A Hugging Face API token was discovered.",
        "A Groq API key was discovered.",
        "A Replicate API token was discovered.",
        "An xAI / Grok API key was discovered.",
        "A DeepSeek API key was discovered."
    ]
    const alertSolution = "Ensure API keys that are publicly accessible are not sensitive in nature."

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

    const openai = /\bsk-[A-Za-z0-9]{48}\b/g
    const openaiproject = /\bsk-proj-[A-Za-z0-9\-_]{48,120}\b/g
    const anthropic = /\bsk-ant-api\d{2}-[A-Za-z0-9\-_]{93,}\b/g
    const huggingface = /\bhf_[A-Za-z0-9]{34}\b/g
    const groq = /\bgsk_[A-Za-z0-9]{52}\b/g
    const replicate = /\br8_[A-Za-z0-9]{40}\b/g
    const xai = /\bxai-[A-Za-z0-9]{80}\b/g
    const deepseek = /\bsk-[a-f0-9]{32}\b/g

    matchAndAlert(openai, 0)
    matchAndAlert(openaiproject, 1)
    matchAndAlert(anthropic, 2)
    matchAndAlert(huggingface, 3)
    matchAndAlert(groq, 4)
    matchAndAlert(replicate, 5)
    matchAndAlert(xai, 6)
    matchAndAlert(deepseek, 7)
}
