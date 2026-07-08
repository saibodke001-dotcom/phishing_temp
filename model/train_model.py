import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pickle
import warnings
from app.utils.logger import logger
import shap

warnings.filterwarnings('ignore')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_DIR = os.path.join(BASE_DIR, 'dataset')
MODEL_DIR = os.path.join(BASE_DIR, 'model')

os.makedirs(DATASET_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

DATASET_PATH = os.path.join(DATASET_DIR, 'phishing_dataset.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')
EXPLAINER_PATH = os.path.join(MODEL_DIR, 'shap_explainer.pkl')

def generate_synthetic_data(num_samples=2000):
    logger.info("Generating synthetic dataset with advanced features...")
    np.random.seed(42)
    labels = np.random.choice([0, 1], size=num_samples)
    
    data = []
    for label in labels:
        if label == 1:
            having_ip_address = np.random.choice([0, 1], p=[0.7, 0.3])
            url_length = np.random.choice([0, 1], p=[0.4, 0.6])
            having_at_symbol = np.random.choice([0, 1], p=[0.8, 0.2])
            prefix_suffix_dash = np.random.choice([0, 1], p=[0.2, 0.8])
            multi_subdomains = np.random.choice([0, 1], p=[0.3, 0.7])
            https_token = np.random.choice([0, 1], p=[0.8, 0.2])
            has_https = np.random.choice([0, 1], p=[0.8, 0.2]) 
            shortining_service = np.random.choice([0, 1], p=[0.7, 0.3])
            count_dots = np.random.randint(1, 10)
            count_digits = np.random.randint(0, 50)
            count_special_chars = np.random.randint(0, 15)
            has_suspicious_words = np.random.choice([0, 1], p=[0.4, 0.6])
            domain_age = np.random.choice([0, 1], p=[0.1, 0.9])
            favicon_mismatch = np.random.choice([0, 1], p=[0.6, 0.4])
            redirects = np.random.choice([0, 1], p=[0.5, 0.5])
            has_hidden_iframes = np.random.choice([0, 1], p=[0.7, 0.3]) # Phishing sites often hide iframes
            has_password_fields = np.random.choice([0, 1], p=[0.2, 0.8]) # Often try to steal passwords
        else:
            having_ip_address = np.random.choice([0, 1], p=[0.99, 0.01])
            url_length = np.random.choice([0, 1], p=[0.9, 0.1])
            having_at_symbol = np.random.choice([0, 1], p=[0.99, 0.01])
            prefix_suffix_dash = np.random.choice([0, 1], p=[0.9, 0.1])
            multi_subdomains = np.random.choice([0, 1], p=[0.9, 0.1])
            https_token = np.random.choice([0, 1], p=[0.99, 0.01])
            has_https = np.random.choice([0, 1], p=[0.1, 0.9])
            shortining_service = np.random.choice([0, 1], p=[0.9, 0.1])
            count_dots = np.random.randint(1, 4)
            count_digits = np.random.randint(0, 10)
            count_special_chars = np.random.randint(0, 5)
            has_suspicious_words = np.random.choice([0, 1], p=[0.95, 0.05])
            domain_age = np.random.choice([0, 1], p=[0.9, 0.1])
            favicon_mismatch = np.random.choice([0, 1], p=[0.95, 0.05])
            redirects = np.random.choice([0, 1], p=[0.9, 0.1])
            has_hidden_iframes = np.random.choice([0, 1], p=[0.99, 0.01])
            has_password_fields = np.random.choice([0, 1], p=[0.8, 0.2])

        data.append([
            having_ip_address, url_length, having_at_symbol, prefix_suffix_dash,
            multi_subdomains, https_token, has_https, shortining_service,
            count_dots, count_digits, count_special_chars, has_suspicious_words,
            domain_age, favicon_mismatch, redirects, has_hidden_iframes, has_password_fields, label
        ])

    columns = [
        'having_ip_address', 'url_length', 'having_at_symbol', 'prefix_suffix_dash',
        'multi_subdomains', 'https_token', 'has_https', 'shortining_service',
        'count_dots', 'count_digits', 'count_special_chars', 'has_suspicious_words',
        'domain_age', 'favicon_mismatch', 'redirects', 'has_hidden_iframes', 'has_password_fields', 'Label'
    ]
    
    df = pd.DataFrame(data, columns=columns)
    df.to_csv(DATASET_PATH, index=False)
    logger.info(f"Synthetic dataset saved to {DATASET_PATH}")
    return df

def train_and_evaluate():
    # 1. Load Data
    df = generate_synthetic_data()
        
    X = df.drop('Label', axis=1)
    y = df['Label']

    # 2. Split Data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 3. Initialize Models
    models = {
        'Logistic Regression': LogisticRegression(max_iter=1000),
        'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42),
        'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42)
    }

    try:
        from xgboost import XGBClassifier
        models['XGBoost'] = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    except ImportError:
        logger.warning("XGBoost not installed. Proceeding with other models.")

    results = {}
    best_model = None
    best_f1 = 0

    logger.info("\n--- Model Training & Comparison ---")
    
    # 4. Train and Evaluate
    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred)
        
        logger.info(f"{name:<20} | F1: {f1:.4f}")

        # Let's prefer Random Forest or Gradient Boosting because SHAP TreeExplainer is better for them
        if f1 > best_f1 and name in ['Random Forest', 'Gradient Boosting', 'XGBoost']:
            best_f1 = f1
            best_model = model
            best_model_name = name

    # If no tree model was best, fallback to RF just to ensure SHAP TreeExplainer works easily
    if not best_model:
        best_model = models['Random Forest']
        best_model_name = 'Random Forest'

    logger.info(f"Best Model Selected for Explainability: {best_model_name}")

    # 5. Save the Best Model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(best_model, f)
    logger.info(f"Model saved to {MODEL_PATH}")

    # 6. Generate SHAP Explainer
    logger.info("Generating SHAP Explainer...")
    # TreeExplainer is fast for RF/XGB/GBM
    explainer = shap.TreeExplainer(best_model)
    with open(EXPLAINER_PATH, 'wb') as f:
        pickle.dump(explainer, f)
    logger.info(f"SHAP Explainer saved to {EXPLAINER_PATH}")

if __name__ == "__main__":
    train_and_evaluate()
