from flask import Blueprint, request, jsonify
from app.models import db, ScanHistory
from feature_extraction import extract_features_async
import pickle
import numpy as np
import os
import asyncio
from app.utils.logger import logger

api_bp = Blueprint('api_routes', __name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_PATH = os.path.join(BASE_DIR, 'model', 'phishing_model.pkl')
EXPLAINER_PATH = os.path.join(BASE_DIR, 'model', 'shap_explainer.pkl')

model = None
explainer = None

try:
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
except FileNotFoundError:
    logger.error("Model not found!")

try:
    with open(EXPLAINER_PATH, 'rb') as f:
        explainer = pickle.load(f)
except FileNotFoundError:
    logger.warning("SHAP explainer not found!")

FEATURE_ORDER = [
    'having_ip_address', 'url_length', 'having_at_symbol', 'prefix_suffix_dash',
    'multi_subdomains', 'https_token', 'has_https', 'shortining_service',
    'count_dots', 'count_digits', 'count_special_chars', 'has_suspicious_words',
    'domain_age', 'favicon_mismatch', 'redirects', 'has_hidden_iframes', 'has_password_fields'
]

@api_bp.route('/analyze', methods=['POST'])
def analyze_url():
    if not model:
        return jsonify({"error": "Model not trained"}), 500

    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({"error": "Invalid URL"}), 400

    try:
        # 1. Extract Features & Intelligence (Async wrapper)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        features_dict, intelligence = loop.run_until_complete(extract_features_async(url))
        
        feature_vector = np.array([[features_dict.get(feat, 0) for feat in FEATURE_ORDER]])
        
        # 2. Predict
        prediction = model.predict(feature_vector)[0]
        if hasattr(model, 'predict_proba'):
            confidence = round(max(model.predict_proba(feature_vector)[0]) * 100, 2)
        else:
            confidence = 90.0
            
        is_phishing = bool(prediction == 1)
        
        # 3. SHAP Explanation
        shap_values_dict = {}
        if explainer:
            shap_vals = explainer.shap_values(feature_vector)
            
            # Extract a 1D array of length 17 for the predicted class
            if isinstance(shap_vals, list):
                class_idx = 1 if is_phishing else 0
                vals_1d = shap_vals[class_idx][0]
            else:
                if len(shap_vals.shape) == 3:
                    class_idx = 1 if is_phishing else 0
                    vals_1d = shap_vals[0, :, class_idx]
                elif len(shap_vals.shape) == 2:
                    vals_1d = shap_vals[0]
                else:
                    vals_1d = shap_vals.flatten()
            
            for i, feat in enumerate(FEATURE_ORDER):
                shap_values_dict[feat] = float(vals_1d[i])
                
            # Sort by absolute impact
            shap_values_dict = dict(sorted(shap_values_dict.items(), key=lambda item: abs(item[1]), reverse=True)[:5])

        # 4. Save to DB
        scan = ScanHistory(url=url, is_phishing=is_phishing, confidence=confidence)
        db.session.add(scan)
        db.session.commit()

        # 5. Return Massive Payload
        return jsonify({
            "url": url,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "features": features_dict,
            "shap_explanation": shap_values_dict,
            "intelligence": intelligence
        })

    except Exception as e:
        logger.error(f"Error analyzing {url}: {e}")
        return jsonify({"error": str(e)}), 500
