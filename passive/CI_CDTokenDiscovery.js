// CI/CD platform tokens — format-anchored, near-zero FP
// Adapted from secretsifter Patterns.java
function scan(ps, msg, src)
{
    const url = msg.getRequestHeader().getURI().toString();
    const body = msg.getResponseBody().toString()
    const alertTitle = [
        "GitHub PAT (Classic) Disclosed (script)",
        "GitHub OAuth Token Disclosed (script)",
        "GitHub Actions Token Disclosed (script)",
        "GitHub Refresh Token Disclosed (script)",
        "GitHub Fine-Grained PAT Disclosed (script)",
        "GitLab PAT Disclosed (script)",
        "GitLab Deploy Token Disclosed (script)",
        "npm Access Token Disclosed (script)",
        "CircleCI API Token Disclosed (script)",
        "Terraform Cloud API Token Disclosed (script)",
        "Pulumi Access Token Disclosed (script)",
        "Buildkite Access Token Disclosed (script)",
        "Netlify Access Token Disclosed (script)",
        "Sentry Auth Token Disclosed (script)",
        "SonarQube Token Disclosed (script)"
    ]
    const alertDesc = [
        "A GitHub Classic PAT was discovered.",
        "A GitHub OAuth token was discovered.",
        "A GitHub Actions token was discovered.",
        "A GitHub refresh token was discovered.",
        "A GitHub Fine-Grained PAT was discovered.",
        "A GitLab PAT was discovered.",
        "A GitLab Deploy token was discovered.",
        "An npm access token was discovered.",
        "A CircleCI API token was discovered.",
        "A Terraform Cloud API token was discovered.",
        "A Pulumi access token was discovered.",
        "A Buildkite access token was discovered.",
        "A Netlify access token was discovered.",
        "A Sentry auth token was discovered.",
        "A SonarQube user token was discovered."
    ]
    const alertSolution = "Ensure CI/CD tokens that are publicly accessible are revoked immediately."

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

    const ghpat = /\bghp_[A-Za-z0-9]{36}\b/g
    const ghoauth = /\bgho_[A-Za-z0-9]{36}\b/g
    const ghactions = /\bghs_[A-Za-z0-9]{36}\b/g
    const ghrefresh = /\bghr_[A-Za-z0-9]{76}\b/g
    const ghfinepat = /\bgithub_pat_[A-Za-z0-9_]{82}\b/g
    const gitlabpat = /\bglpat-[A-Za-z0-9\-_]{20}\b/g
    const gitlabdeploy = /\bgldt-[A-Za-z0-9\-_]{20}\b/g
    const npmtoken = /\bnpm_[A-Za-z0-9]{36}\b/g
    const circleci = /\bccipat_[A-Za-z0-9]{40,}\b/g
    const tfcloud = /\bat\.[A-Za-z0-9]{90,}\b/g
    const pulumi = /\bpul-[a-f0-9]{40}\b/g
    const buildkite = /\bbkua_[A-Za-z0-9]{40}\b/g
    const netlify = /\bnfp_[A-Za-z0-9]{36,}\b/g
    const sentry = /\bsntrys_[A-Za-z0-9]{64,}\b/g
    const sonarqube = /\b(?:squ|sqp)_[a-f0-9]{40}\b/g

    matchAndAlert(ghpat, 0)
    matchAndAlert(ghoauth, 1)
    matchAndAlert(ghactions, 2)
    matchAndAlert(ghrefresh, 3)
    matchAndAlert(ghfinepat, 4)
    matchAndAlert(gitlabpat, 5)
    matchAndAlert(gitlabdeploy, 6)
    matchAndAlert(npmtoken, 7)
    matchAndAlert(circleci, 8)
    matchAndAlert(tfcloud, 9)
    matchAndAlert(pulumi, 10)
    matchAndAlert(buildkite, 11)
    matchAndAlert(netlify, 12)
    matchAndAlert(sentry, 13)
    matchAndAlert(sonarqube, 14)
}
