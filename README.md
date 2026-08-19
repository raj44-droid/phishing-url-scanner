# Phishing URL Detector

A Flask-based cybersecurity web application that analyzes URLs for common phishing indicators and generates an explainable risk score.

 # Overview

Phishing attacks use deceptive URLs to trick users into revealing sensitive information such as passwords, banking details, and account credentials.

**Phishing URL Detector** analyzes a submitted URL using multiple heuristic security checks and classifies it as:

- 🟢 Safe
- 🟡 Suspicious
- 🔴 Dangerous

The application also provides detailed findings explaining why a URL was assigned its risk score.

## ✨ Features

- 🔍 URL phishing analysis
- 🔐 HTTPS detection
- 🌐 IP address detection
- ⚠️ Phishing keyword detection
- 🔗 URL shortener detection
- 🌍 Suspicious TLD detection
- 🧩 Excessive subdomain detection
- 🚨 `@` symbol phishing detection
- 🔤 Punycode/IDN detection
- 🔢 URL encoding analysis
- 📏 URL length analysis
- 🚪 Non-standard port detection
- 📊 Risk score from 0–10
- 🛡️ Safe / Suspicious / Dangerous classification
- 💡 Explainable security findings
- 🌑 Cybersecurity-themed interface
- 📱 Responsive web design

## 🧠 How It Works

The current version uses **rule-based heuristic analysis**.

The submitted URL is analyzed for multiple suspicious characteristics. Each detected indicator contributes to an overall risk score.

### Detection Pipeline

```text
User enters URL
       ↓
URL Validation
       ↓
URL Parsing
       ↓
Security Feature Analysis
       ↓
Risk Score Calculation
       ↓
Threat Classification
       ↓
Detailed Security Report
