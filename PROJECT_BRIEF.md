# Project Brief: PhishGuard
## Hybrid AI-Based Phishing URL Detection System

**Project Type:** Mini AI / Cybersecurity Project  
**Development Approach:** Hybrid Rule-Based Detection + Machine Learning  
**Primary Language:** Python  
**Initial Deployment:** Localhost  
**Version:** 1.0

---

## 1. Project Overview

PhishGuard is a lightweight web-based application designed to analyze URLs and identify potential phishing websites using a hybrid detection approach.

The application combines rule-based URL analysis with a machine learning classification model to evaluate suspicious URL characteristics and predict whether a URL is potentially phishing or legitimate.

The main objective is to develop a practical cybersecurity prototype that demonstrates how Artificial Intelligence and Machine Learning can support basic phishing URL detection.

## 2. Project Objectives

1. Understand common URL characteristics associated with phishing attacks.
2. Implement rule-based URL analysis using Python.
3. Develop a Machine Learning model to classify phishing and legitimate URLs.
4. Combine both detection approaches into a unified risk assessment system.
5. Build a simple web interface for URL analysis.
6. Evaluate the model using appropriate classification metrics.
7. Run the application locally and publish its source code to GitHub.

## 3. Core Features

### A. URL Feature Extraction
Extract relevant characteristics from submitted URLs, including:

- URL length.
- HTTPS availability.
- IP address usage.
- Number of subdomains.
- Special character frequency.
- Suspicious keywords.
- URL encoding and obfuscation patterns.
- Domain structure.

### B. Rule-Based Detection
Analyze URL characteristics using predefined security rules.

Each suspicious indicator contributes to a risk score. The system must explain which characteristics triggered the rules.

### C. Machine Learning Detection
Train a Random Forest Classifier using a labeled phishing URL dataset.

The model should:

- Learn patterns from phishing and legitimate URLs.
- Predict the URL classification.
- Provide class probabilities where supported.
- Be evaluated using precision, recall, F1-score, and confusion matrix.

### D. Hybrid Risk Assessment
Combine rule-based findings and machine learning predictions.

The system should display:

- Rule-based analysis results.
- Machine learning prediction.
- Combined risk classification.
- Reasons behind the assessment.

The combination method must be documented and should not blindly treat model probability as a guaranteed risk score.

### E. Web Interface
Build a lightweight interface using Streamlit.

Users should be able to:

1. Enter a URL.
2. Start an analysis.
3. View detection results.
4. Review suspicious indicators.
5. Understand why the URL received its classification.

## 4. Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3.11 |
| Web Framework | Streamlit |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn |
| Algorithm | Random Forest |
| URL Parsing | urllib.parse |
| Model Serialization | Joblib |
| Version Control | Git and GitHub |

## 5. Project Architecture

The application follows a simple modular architecture:

1. User submits a URL through Streamlit.
2. URL feature extraction processes its characteristics.
3. Rule-based detection evaluates predefined indicators.
4. Machine learning predicts the URL classification.
5. Risk assessment combines both results.
6. Streamlit displays the final analysis report.

## 6. Dataset Requirements

The project requires a publicly available labeled phishing URL dataset containing:

- URL samples.
- Phishing labels.
- Legitimate URL labels.
- Dataset source and license information.

Dataset preparation must include:

- Missing-value inspection.
- Duplicate removal.
- Label normalization.
- Class distribution analysis.
- Training and testing split.

The test dataset must not be used during model training or feature-selection decisions.

## 7. Development Scope and Limitations

This is an educational prototype, not a production-grade phishing detection platform.

The initial version will:

- Analyze URL strings without opening or visiting submitted websites.
- Use locally available detection logic and ML models.
- Avoid external threat intelligence APIs.
- Avoid collecting or transmitting submitted URLs.
- Display risk indicators rather than guarantee whether a website is malicious.

The application does not perform website content inspection, malware analysis, browser protection, or real-time threat intelligence verification.

## 8. Development Milestones

| Milestone | Deliverable |
|---|---|
| M1 - Environment Setup | Python environment and dependencies |
| M2 - Dataset Preparation | Clean and validated dataset |
| M3 - Feature Engineering | URL feature extraction module |
| M4 - Model Development | Trained and evaluated Random Forest model |
| M5 - Rule-Based Detection | Rule engine and risk scoring |
| M6 - Hybrid Integration | Combined detection pipeline |
| M7 - Web Interface | Functional Streamlit application |
| M8 - Testing & Documentation | Test results and README |
| M9 - Version Control | GitHub repository |

## 9. Expected Deliverables

At completion, the project should contain:

1. Functional Python source code.
2. Prepared phishing URL dataset or reproducible dataset acquisition instructions.
3. Trained Machine Learning model.
4. Rule-based detection module.
5. Hybrid analysis module.
6. Streamlit web application.
7. Model evaluation report.
8. GitHub repository with documentation.

## 10. Definition of Done

The project is considered complete when:

- The application runs locally without errors.
- Users can submit URLs for analysis.
- Both detection approaches operate correctly.
- The system provides understandable analysis results.
- The ML model has been evaluated on unseen test data.
- The application has been tested with representative phishing and legitimate URL samples.
- Source code and setup instructions are available in GitHub.

**Final Goal:** Deliver a small, functional, locally deployable AI-assisted cybersecurity application that demonstrates the practical application of Machine Learning in phishing URL detection.