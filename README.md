<div align="center">
  <img src="https://img.icons8.com/color/96/000000/shield.png" alt="PhishGuard Logo" width="80"/>
  
  # PhishGuard Enterprise Edition
  
  **State-of-the-Art Machine Learning Phishing Detection**
  
  [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
  [![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey.svg)](https://flask.palletsprojects.com/)
  [![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker)](https://www.docker.com/)
  [![TailwindCSS](https://img.shields.io/badge/Tailwind-CSS-38B2AC.svg?logo=tailwind-css)](https://tailwindcss.com/)
  
</div>

---

## 🚀 Overview

PhishGuard Enterprise is a high-performance, modular cybersecurity SaaS prototype designed to detect phishing URLs in real-time. It leverages advanced Machine Learning models (Random Forest, Gradient Boosting, XGBoost), asynchronous HTML parsing, and SHAP (SHapley Additive exPlanations) to not only catch threats but explicitly explain **why** a site was flagged.

## ✨ Enterprise Features

- **Asynchronous Threat Intel**: Uses `httpx` and `BeautifulSoup4` to asynchronously fetch target HTML, inspecting for hidden iframes and suspicious password fields instantly.
- **Explainable AI (XAI)**: Integrated `SHAP` TreeExplainer provides human-readable context. Instead of just a "Phishing" label, the UI generates interactive Radar charts showing exactly which lexical or DOM features triggered the alarm.
- **Ultra-Premium UI**: Fully responsive, single-page application feel with a Glassmorphism aesthetic, `particles.js` cyber-background, dark mode default, and `Chart.js` dynamic visualizations.
- **Microservice Ready**: Implements Flask Blueprints and an isolated REST API endpoint (`/api/v1/analyze`), backed by an SQLite tracking database via SQLAlchemy.

## 🧠 Architecture Setup

```mermaid
graph TD;
    User[User / Browser] -->|POST URL| UI(Flask UI Blueprint)
    UI --> API(Flask API Blueprint)
    API --> Extractor(Async Feature Extractor)
    Extractor -->|httpx| Web(Target Website)
    API --> ML(XGBoost / RF Model)
    API --> SHAP(SHAP Explainer)
    API --> DB[(SQLite: ScanHistory)]
    ML --> UI
```

## 🛠️ Installation & Setup

### Option 1: Docker (Recommended)
Spin up the entire application stack in one command:
```bash
docker-compose up --build
```
The app will automatically train the model on first launch and serve at `http://localhost:5000`.

### Option 2: Local Python Environment
1. Clone the repository and navigate to the directory.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database and train the ML model:
   ```bash
   python model/train_model.py
   ```
4. Run the backend:
   ```bash
   python app.py
   ```

## 📊 API Documentation

### POST `/api/v1/analyze`
**Request:**
```json
{
  "url": "http://secure-login-update.com"
}
```
**Response:**
```json
{
  "confidence": 98.4,
  "features": {
    "has_password_fields": 1,
    "url_length": 0,
    ...
  },
  "is_phishing": true,
  "shap_explanation": {
    "has_password_fields": 1.25,
    "having_ip_address": 0.84,
    ...
  },
  "url": "http://secure-login-update.com"
}
```
