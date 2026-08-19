from flask import Flask, render_template, request
import re
from urllib.parse import urlparse

app = Flask(__name__)

# =========================================
# PHISHING DETECTION DATA
# =========================================

PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'secure',
    'account', 'update', 'confirm',
    'banking', 'paypal', 'amazon',
    'microsoft', 'apple', 'google',
    'facebook', 'netflix', 'ebay',
    'password', 'credential', 'wallet'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co',
    'goo.gl', 'ow.ly', 'buff.ly',
    'is.gd', 'rb.gy', 'short.io',
    'cutt.ly', 'tiny.cc'
]

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.xyz', '.top', '.click', '.loan',
    '.win', '.date', '.download',
    '.racing', '.review', '.bid'
]

# =========================================
# URL ANALYSIS
# =========================================

def analyze_url(url):

    findings = []
    risk = 0

    try:
        parsed = urlparse(
            url if url.startswith('http')
            else 'https://' + url
        )

        host = parsed.hostname or ''
        full = url.lower()

    except Exception:
        return 10, [{
            'label': 'Invalid URL',
            'status': 'fail',
            'detail': 'Could not parse this as a valid URL.'
        }]

    # =====================================
    # HTTPS CHECK
    # =====================================

    if parsed.scheme == 'https':

        findings.append({
            'label': 'HTTPS enabled',
            'status': 'pass',
            'detail': 'Connection is encrypted.'
        })

    else:

        risk += 2

        findings.append({
            'label': 'No HTTPS',
            'status': 'fail',
            'detail': 'Traffic is unencrypted.'
        })

    # =====================================
    # IP ADDRESS DETECTION
    # =====================================

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):

        risk += 3

        findings.append({
            'label': 'IP address used',
            'status': 'fail',
            'detail': 'Legitimate sites usually use domains.'
        })

    # =====================================
    # PHISHING KEYWORDS
    # =====================================

    matched = [
        k for k in PHISHING_KEYWORDS
        if k in full
    ]

    if matched:

        risk += min(len(matched) * 1.5, 4)

        findings.append({
            'label': f'Phishing keywords ({len(matched)})',
            'status': 'warn',
            'detail': f"Detected: {', '.join(matched[:4])}"
        })

    else:

        findings.append({
            'label': 'No phishing keywords',
            'status': 'pass',
            'detail': 'No suspicious brand impersonation.'
        })

    # =====================================
    # SUBDOMAIN DEPTH
    # =====================================

    dots = host.count('.')

    if dots > 3:

        risk += 1.5

        findings.append({
            'label': 'Too many subdomains',
            'status': 'warn',
            'detail': f'{dots} dots detected.'
        })

    else:

        findings.append({
            'label': 'Domain structure normal',
            'status': 'pass',
            'detail': f'{dots} subdomain level(s).'
        })

    # =====================================
    # URL SHORTENERS
    # =====================================

    if any(
        host == s or host.endswith('.' + s)
        for s in URL_SHORTENERS
    ):

        risk += 2

        findings.append({
            'label': 'URL shortener detected',
            'status': 'warn',
            'detail': 'Shorteners hide the destination.'
        })

    # =====================================
    # SUSPICIOUS TLD
    # =====================================

    tld_match = next(
        (
            t for t in SUSPICIOUS_TLDS
            if host.endswith(t)
        ),
        None
    )

    if tld_match:

        risk += 2

        findings.append({
            'label': f'Suspicious TLD ({tld_match})',
            'status': 'fail',
            'detail': 'Frequently abused for phishing.'
        })

    else:

        findings.append({
            'label': 'TLD looks normal',
            'status': 'pass',
            'detail': 'No risky TLD detected.'
        })

    # =====================================
    # @ SYMBOL TRICK
    # =====================================

    if '@' in url:

        risk += 3

        findings.append({
            'label': '@ symbol detected',
            'status': 'fail',
            'detail': 'Classic phishing redirection trick.'
        })

    # =====================================
    # PUNYCODE / IDN
    # =====================================

    if 'xn--' in host:

        risk += 2

        findings.append({
            'label': 'Punycode domain',
            'status': 'warn',
            'detail': 'Possible lookalike domain.'
        })

    # =====================================
    # URL ENCODING
    # =====================================

    enc_count = len(
        re.findall(r'%[0-9a-fA-F]{2}', url)
    )

    if enc_count > 3:

        risk += 1

        findings.append({
            'label': f'Heavy encoding ({enc_count}x)',
            'status': 'warn',
            'detail': 'Encoded URLs can hide malicious content.'
        })

    # =====================================
    # URL LENGTH
    # =====================================

    if len(url) > 120:

        risk += 1

        findings.append({
            'label': 'Very long URL',
            'status': 'warn',
            'detail': f'{len(url)} characters.'
        })

    else:

        findings.append({
            'label': 'URL length normal',
            'status': 'pass',
            'detail': f'{len(url)} characters.'
        })

    # =====================================
    # PORT CHECK
    # =====================================

    if parsed.port and parsed.port not in (80, 443):

        risk += 1

        findings.append({
            'label': f'Non-standard port ({parsed.port})',
            'status': 'warn',
            'detail': 'Unusual ports may be suspicious.'
        })

    # FINAL SCORE

    score = min(int(risk), 10)

    return score, findings

# =========================================
# LOCAL AI ANALYSIS
# =========================================

def get_ai_analysis(url, score, findings):

    issues = [
        f['label']
        for f in findings
        if f['status'] != 'pass'
    ]

    if score <= 2:

        return (
            "This URL appears relatively safe based on heuristic analysis. "
            "No major phishing indicators were detected."
        )

    elif score <= 5:

        return (
            "This URL contains suspicious characteristics including: "
            + ", ".join(issues[:3]) +
            ". Proceed with caution before entering credentials."
        )

    else:

        return (
            "This URL exhibits multiple high-risk phishing indicators including: "
            + ", ".join(issues[:4]) +
            ". Avoid visiting or submitting sensitive information."
        )

# =========================================
# VERDICT
# =========================================

def get_verdict(score):

    if score <= 2:
        return 'Safe', 'safe'

    elif score <= 5:
        return 'Suspicious', 'warning'

    else:
        return 'Dangerous', 'danger'

# =========================================
# ROUTE
# =========================================

@app.route("/", methods=["GET", "POST"])

def home():

    result = None
    findings = []
    score = 0

    verdict_label = ''
    verdict_class = ''

    ai_analysis = ''
    url = ''

    if request.method == "POST":

        url = request.form.get(
            'url',
            ''
        ).strip()

        if url:

            score, findings = analyze_url(url)

            verdict_label, verdict_class = get_verdict(score)

            ai_analysis = get_ai_analysis(
                url,
                score,
                findings
            )

            result = True

    return render_template(

        "index.html",

        result=result,
        url=url,

        findings=findings,

        score=score,
        score_pct=score * 10,

        verdict_label=verdict_label,
        verdict_class=verdict_class,

        ai_analysis=ai_analysis,
    )

# =========================================
# RUN APP
# =========================================

if __name__ == "__main__":
    app.run(debug=True)