import re
from urllib.parse import urlparse


def detect_phishing(url):

    score = 0
    reasons = []

    # Convert URL to lowercase for checking
    url_lower = url.lower()

    # Parse URL
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname or ""
    except Exception:
        hostname = ""

    # 1. Check URL length
    if len(url) > 75:
        score += 1
        reasons.append("The URL is unusually long.")

    # 2. Check @ symbol
    if "@" in url:
        score += 2
        reasons.append("The URL contains an @ symbol.")

    # 3. Check IP address
    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        score += 2
        reasons.append(
            "The URL uses an IP address instead of a domain name."
        )

    # 4. Check number of subdomains
    parts = hostname.split(".")

    if len(parts) > 3 and not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hostname):
        score += 1
        reasons.append(
            "The URL contains an unusually large number of subdomains."
        )

    # 5. Check for HTTPS
    if not url_lower.startswith("https://"):
        reasons.append(
            "The website does not use HTTPS."
        )

    # 6. Check suspicious words
    suspicious_words = [
        "login",
        "verify",
        "verification",
        "account",
        "update",
        "secure",
        "bank",
        "password",
        "signin",
        "confirm",
        "free",
        "winner"
    ]

    found_words = []

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    if found_words:
        score += 1
        if len(found_words) == 1:
            reasons.append(
                "The URL contains a suspicious keyword: "
                + found_words[0]
            )
        else:
            score += 2
            reasons.append(
                "The URL contains suspicious keywords: "
                + ", ".join(found_words)
            )

    # 7. Check suspicious characters
    suspicious_characters = ["%", "$", "^", "*", "~"]

    found_characters = []

    for character in suspicious_characters:
        if character in url:
            found_characters.append(character)

    if found_characters:
        score += 1
        reasons.append(
            "The URL contains unusual characters: "
            + ", ".join(found_characters)
        )

    # 8. Check hyphen in domain
    if "-" in hostname:
        score += 1
        reasons.append(
            "The domain contains a hyphen."
        )

    # 9. Check excessive dots
    if hostname.count(".") > 3:
        score += 1
        reasons.append(
            "The domain contains an unusually high number of dots."
        )

    # 10. Check URL shortening services
    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly"
    ]

    if hostname in shortener_domains:
        score += 2
        reasons.append(
            "The URL uses a URL shortening service."
        )

    # Determine result and risk level
    if score >= 5:
        result = "Potentially Phishing"
        risk_level = "High"

    elif score >= 2:
        result = "Suspicious"
        risk_level = "Medium"

    else:
        result = "Likely Safe"
        risk_level = "Low"

    return result, score, risk_level, reasons