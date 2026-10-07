import pandas as pd
import numpy as np

from sklearn.model_selection import GroupShuffleSplit
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

import joblib


# ============================================================
# 1. LOAD DATASET
# ============================================================

print("=" * 70)
print("V6 MODEL TRAINING")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")

print("Rows:", len(df))
print("Columns:", len(df.columns))


# ============================================================
# 2. KEEP ONLY URL-BASED INFORMATION
# ============================================================

def extract_features(url):

    url = str(url)

    url_lower = url.lower()

    # Remove protocol for easier analysis
    clean_url = url_lower

    if clean_url.startswith("https://"):
        clean_url = clean_url[8:]

    elif clean_url.startswith("http://"):
        clean_url = clean_url[7:]

    # Separate domain from path
    domain = clean_url.split("/")[0]

    path = ""

    if "/" in clean_url:
        path = clean_url.split("/", 1)[1]

    # Query and fragment
    query = ""

    if "?" in path:
        path_without_query, query = path.split("?", 1)
    else:
        path_without_query = path

    fragment = ""

    if "#" in path_without_query:
        path_without_fragment, fragment = path_without_query.split("#", 1)
    else:
        path_without_fragment = path_without_query

    # Basic character counts
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    special_characters = sum(
        not c.isalnum()
        for c in url
    )

    suspicious_characters = sum(
        url.count(c)
        for c in ["@", "%", "$", "^", "*", "~"]
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

    # IP address detection
    import re

    is_ip = 1 if re.fullmatch(
        r"\d{1,3}(\.\d{1,3}){3}",
        domain
    ) else 0

    # HTTPS
    is_https = 1 if url_lower.startswith("https://") else 0

    # Feature dictionary
    features = {

        "URLLength": len(url),

        "DomainLength": len(domain),

        "IsDomainIP": is_ip,

        "IsHTTPS": is_https,

        "NoOfDots": domain.count("."),

        "NoOfHyphens": domain.count("-"),

        "NoOfSubDomains": max(domain.count(".") - 1, 0),

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

        "LetterRatio": letters / len(url) if len(url) > 0 else 0,

        "DigitRatio": digits / len(url) if len(url) > 0 else 0,

        "SpecialCharacterRatio":
            special_characters / len(url)
            if len(url) > 0 else 0,

        "HasSuspiciousWord":
            1 if found_words else 0,

        "SuspiciousWordCount":
            len(found_words),

        "HasObfuscation":
            1 if suspicious_characters > 0 else 0,

        "TLDLength":
            len(domain.split(".")[-1])
            if "." in domain else 0
    }

    return features


# ============================================================
# 3. EXTRACT FEATURES
# ============================================================

print("\nExtracting URL features...")

feature_rows = []

for url in df["URL"]:

    feature_rows.append(
        extract_features(url)
    )

X = pd.DataFrame(feature_rows)

y = df["label"].copy()

print("Feature matrix:", X.shape)


# ============================================================
# 4. DOMAIN-BASED TRAIN/TEST SPLIT
# ============================================================

print("\nCreating domain-separated train/test split...")

groups = df["Domain"].astype(str)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(X, y, groups=groups)
)

X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()

y_train = y.iloc[train_idx].copy()
y_test = y.iloc[test_idx].copy()

print("Original training samples:", len(X_train))
print("Original test samples:", len(X_test))


# ============================================================
# 5. BALANCE THE TRAINING DATA
# ============================================================

print("\nBalancing training data...")

train_data = X_train.copy()

train_data["label"] = y_train.values

class_0 = train_data[
    train_data["label"] == 0
]

class_1 = train_data[
    train_data["label"] == 1
]

print("Original class 0:", len(class_0))
print("Original class 1:", len(class_1))


# Use the smaller class size
sample_size = min(
    len(class_0),
    len(class_1)
)

class_0_balanced = class_0.sample(
    n=sample_size,
    random_state=42
)

class_1_balanced = class_1.sample(
    n=sample_size,
    random_state=42
)

balanced_train = pd.concat(
    [
        class_0_balanced,
        class_1_balanced
    ],
    axis=0
)

balanced_train = balanced_train.sample(
    frac=1,
    random_state=42
)

X_train_balanced = balanced_train.drop(
    columns=["label"]
)

y_train_balanced = balanced_train["label"]

print("Balanced class 0:", sum(y_train_balanced == 0))
print("Balanced class 1:", sum(y_train_balanced == 1))

print(
    "Balanced training samples:",
    len(X_train_balanced)
)


# ============================================================
# 6. TRAIN RANDOM FOREST
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    n_jobs=-1,
    max_depth=15,
    min_samples_leaf=3,
    class_weight=None
)

model.fit(
    X_train_balanced,
    y_train_balanced
)


# ============================================================
# 7. EVALUATE MODEL
# ============================================================

print("\nEvaluating model...")

predictions = model.predict(X_test)


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    zero_division=0
)

cm = confusion_matrix(
    y_test,
    predictions
)


print("\n" + "=" * 70)
print("V6 MODEL RESULTS")
print("=" * 70)

print(
    f"Accuracy : {accuracy * 100:.2f}%"
)

print(
    f"Precision: {precision * 100:.2f}%"
)

print(
    f"Recall   : {recall * 100:.2f}%"
)

print(
    f"F1 Score : {f1 * 100:.2f}%"
)

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# 8. FEATURE IMPORTANCE
# ============================================================

print("\n" + "=" * 70)
print("TOP FEATURE IMPORTANCE")
print("=" * 70)

importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    by="Importance",
    ascending=False
)

print(
    importance.head(15).to_string(
        index=False
    )
)


# ============================================================
# 9. SAVE MODEL
# ============================================================

model_data = {
    "model": model,
    "features": list(X.columns)
}

joblib.dump(
    model_data,
    "phishing_url_model_v6.pkl"
)

print("\n" + "=" * 70)
print("MODEL SAVED")
print("=" * 70)

print(
    "Saved as: phishing_url_model_v6.pkl"
)