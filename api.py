from flask import Flask, request, jsonify
from flask_cors import CORS  # Add this import
import joblib
import numpy as np

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Load the model and feature names
model_data = joblib.load('phishing_classifier.pkl')
model = model_data['model']
feature_names = model_data['feature_names']

# Feature extraction function
def extract_features(url, html_content):
    features = {}
    features['having_IP'] = 1 if any(c.isdigit() for c in url.split('://')[1].split('/')[0]) else -1
    features['URL_Length'] = 1 if len(url) >= 54 else -1
    features['Shortining_Service'] = 1 if any(service in url for service in ['bit.ly', 'tinyurl']) else -1
    features['having_At_Symbol'] = 1 if '@' in url else -1
    features['double_slash_redirecting'] = 1 if '//' in url[7:] else -1
    features['Prefix_Suffix'] = 1 if '-' in url.split('://')[1].split('/')[0] else -1
    features['having_Sub_Domain'] = 1 if url.count('.') > 2 else -1
    features['HTTPS_token'] = 1 if 'https' in url.split('://')[1].split('/')[0] else -1
    features['Request_URL'] = 1 if 'src="' in html_content else -1
    features['URL_of_Anchor'] = 1 if '<a href="' in html_content else -1
    features['Links_in_tags'] = 1 if '<script' in html_content or '<link' in html_content else -1
    features['SFH'] = 1 if 'action="' in html_content else -1
    features['Submitting_to_email'] = 1 if 'mailto:' in html_content else -1
    features['on_mouseover'] = 1 if 'onmouseover' in html_content else -1
    features['RightClick'] = 1 if 'event.button' in html_content else -1
    features['popUpWidnow'] = 1 if 'window.open' in html_content else -1
    features['Iframe'] = 1 if '<iframe' in html_content else -1
    features['SSLfinal_State'] = 1
    features['Domain_registeration_length'] = -1
    features['Favicon'] = 1
    features['port'] = 1
    features['Abnormal_URL'] = 1
    features['Redirect'] = 0
    features['age_of_domain'] = -1
    features['DNSRecord'] = 1
    features['web_traffic'] = 0
    features['Page_Rank'] = -1
    features['Google_Index'] = 1
    features['Links_pointing_to_page'] = 0
    features['Statistical_report'] = 1
    return [features[name] for name in feature_names]

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'Welcome to the Phishing Detection API',
        'endpoint': '/predict',
        'method': 'POST',
        'expected_input': {
            'url': 'string',
            'html': 'string'
        }
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    url = data.get('url', '')
    html_content = data.get('html', '')
    features = extract_features(url, html_content)
    prediction = model.predict([features])[0]
    probability = model.predict_proba([features])[0]
    return jsonify({
        'is_phishing': bool(prediction == 1),
        'confidence': float(max(probability))
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)