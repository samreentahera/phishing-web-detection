# Phishing Web Detection System

A web-based phishing URL detection system built using Python, Flask, rule-based security analysis, and machine-learning-assisted URL analysis.

## 📌 Project Overview

Phishing attacks often use deceptive URLs to trick users into visiting malicious websites or revealing sensitive information.

This project analyzes a submitted URL and provides an explainable security assessment based on suspicious URL characteristics.

The system uses two complementary approaches:

1. **Rule-Based Security Analysis** – the primary assessment.
2. **Machine-Learning-Assisted Analysis** – an experimental secondary signal.

The machine-learning signal is not used as a standalone verdict.

## ✨ Features

- URL-based phishing detection
- Explainable security analysis
- Risk score calculation
- Low, Medium, and High risk levels
- Detection of suspicious URL characteristics
- Machine-learning-assisted URL analysis
- ML confidence score
- Flask-based web interface
- Easy-to-understand results
- Separate explanation of ML limitations

## 🔍 Security Analysis

The rule-based detector checks URL characteristics such as:

- Unusually long URLs
- IP addresses instead of domain names
- Suspicious keywords
- Excessive subdomains
- Suspicious characters
- Hyphens in domain names
- Excessive dots
- URL shortening services
- Other suspicious URL patterns

The system calculates a risk score based on these characteristics.

### Risk Levels

| Risk Score | Risk Level |
|------------|------------|
| 0–1 | Low |
| 2–4 | Medium |
| 5+ | High |

## 🤖 Machine Learning Component

The project also includes a machine-learning model trained using the **PhiUSIIL Phishing URL Dataset**.

The model analyzes URL characteristics including:

- URL length
- Domain length
- HTTPS usage
- Domain structure
- Number of digits
- Number of letters
- URL symbols
- Subdomains
- Suspicious words
- Character ratios
- Other URL-based features

The ML component provides an additional experimental signal and confidence score.

### Important Limitation

The machine-learning model is trained on a specific dataset and may produce false positives when tested on unseen real-world URLs.

Therefore, the ML output is intentionally presented as an **experimental supporting signal** rather than a standalone determination of whether a website is safe.

## 🏗️ System Architecture

```text
User enters URL
       │
       ▼
Flask Web Application
       │
       ├───────────────┐
       ▼               ▼
Rule-Based         ML-Based
Analysis           Analysis
       │               │
       ▼               ▼
Risk Score          ML Signal
Risk Level          Confidence
Reasons
       │               │
       └───────┬───────┘
               ▼
        Results displayed
        to the user