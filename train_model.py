import joblib
import re
import pandas as pd

# Load the trained model
model = joblib.load('phishing_model.pkl')  # Ensure the model file is in the working directory

# Feature extraction function
def extract_features(url):
    """
    Extracts features from the given URL.
    """
    return {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_slashes': url.count('/'),
        'num_special_chars': sum([url.count(c) for c in ['@', '-', '_', '%']]),
        'has_https': 1 if url.startswith('https') else 0,
        'has_ip': 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        'num_keywords': sum([1 for word in ['login', 'secure', 'account'] if word in url.lower()])
    }

# Function to test a URL
def test_url(url):
    """
    Tests whether a given URL is phishing or non-phishing.
    """
    # Extract features for the URL
    features = extract_features(url)
    features_df = pd.DataFrame([features])  # Convert to DataFrame for prediction

    # Predict using the trained model
    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == 1 else "Non-Phishing"
    return result

# Main program to get user input
print("Phishing URL Detection")
print("=======================")

while True:
    # Get user input
    user_url = input("\nEnter a URL to test (or type 'exit' to quit): ").strip()
    
    # Exit condition
    if user_url.lower() == 'exit':
        print("Exiting the program. Goodbye!")
        break
    
    # Check the URL
    result = test_url(user_url)
    print(f"URL: {user_url} -> {result}")