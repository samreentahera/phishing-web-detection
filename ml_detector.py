import pandas as pd
import joblib
import re
from urllib.parse import urlparse


# Load Version 6 model
saved_model = joblib.load("phishing_url_model_v6.pkl")

model = saved_model["model"]
feature_names = saved_model["features"]


def extract_features(url):

    url = str(url)
    url_lower = url.lower()

    # Remove protocol for domain/path analysis
    clean_url = url_lower

    if clean_url.startswith("https://"):
        clean_url = clean_url[8:]

    elif clean_url.startswith("http://"):
        clean_url = clean_url[7:]

    # Extract domain
    domain = clean_url.split("/")[0]

    # Extract path
    path = ""

    if "/" in clean_url:
        path = clean_url.split("/", 1)[1]

    # Extract query
    query = ""

    if "?" in path:
        path_without_query, query = path.split("?", 1)
    else:
        path_without_query = path

    # Extract fragment
    fragment = ""

    if "#" in path_without_query:
        path_without_fragment, fragment = path_without_query.split("#", 1)
    else:
        path_without_fragment = path_without_query

    # Count letters and digits
    letters = sum(character.isalpha() for character in url)
    digits = sum(character.isdigit() for character in url)

    # Count special characters
    special_characters = sum(
        not character.isalnum()
        for character in url
    )

    # Suspicious characters
    suspicious_character_list = [
        "@",
        "%",
        "$",
        "^",
        "*",
        "~"
    ]

    suspicious_characters = sum(
        url.count(character)
        for character in suspicious_character_list
    )

    # Suspicious words
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

    found_words = [
        word
        for word in suspicious_words
        if word in url_lower
    ]

    # Check whether domain is an IP address
    is_ip = 1 if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        domain
    ) else 0

    # Check HTTPS
    is_https = 1 if url_lower.startswith("https://") else 0

    # Create feature dictionary
    features = {

        "URLLength": len(url),

        "DomainLength": len(domain),

        "IsDomainIP": is_ip,

        "IsHTTPS": is_https,

        "NoOfDots": domain.count("."),

        "NoOfHyphens": domain.count("-"),

        "NoOfSubDomains": max(
            domain.count(".") - 1,
            0
        ),

        "PathLength": len(path_without_fragment),

        "QueryLength": len(query),

        "FragmentLength": len(fragment),

        "NoOfLetters": letters,

        "NoOfDigits": digits,

        "NoOfSlashes": url.count("/"),

        "NoOfEquals": url.count("="),

        "NoOfQuestionMarks": url.count("?"),

        "NoOfAmpersands": url.count("&"),

        "NoOfAtSymbols": url.count("@"),

        "NoOfPercentSymbols": url.count("%"),

        "NoOfColons": url.count(":"),

        "NoOfSemicolons": url.count(";"),

        "NoOfUnderscores": url.count("_"),

        "NoOfSuspiciousCharacters": suspicious_characters,

        "LetterRatio": (
            letters / len(url)
            if len(url) > 0
            else 0
        ),

        "DigitRatio": (
            digits / len(url)
            if len(url) > 0
            else 0
        ),

        "SpecialCharacterRatio": (
            special_characters / len(url)
            if len(url) > 0
            else 0
        ),

        "HasSuspiciousWord": (
            1 if found_words else 0
        ),

        "SuspiciousWordCount": len(found_words),

        "HasObfuscation": (
            1 if suspicious_characters > 0 else 0
        ),

        "TLDLength": (
            len(domain.split(".")[-1])
            if "." in domain
            else 0
        )
    }

    # Return features in exactly the order
    # expected by the trained model
    return [
        features[name]
        for name in feature_names
    ]


def predict_url(url):

    features = extract_features(url)

    # Convert to DataFrame with feature names
    features_df = pd.DataFrame(
        [features],
        columns=feature_names
    )

    # Make prediction
    prediction = model.predict(features_df)[0]

    # Dataset labels:
    # 1 = Legitimate
    # 0 = Phishing

    if prediction == 0:
        result = "Potentially Phishing"
    else:
        result = "Likely Safe"

    # Get prediction probability
    probabilities = model.predict_proba(features_df)[0]

    confidence = round(
        max(probabilities) * 100,
        2
    )

    return result, confidence