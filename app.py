import random
from flask import Flask, request, jsonify, render_template
import re
import sqlite3
import requests
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# Database setup
DB_NAME = "phished_urls.db"
phished_urls_set = set()  # To store imported phishing URLs
clicked_emails = []  # To store email IDs of users who clicked the fake URLs

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS phished_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        source TEXT,
        category TEXT,
        detection_date TEXT
    )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized and ready.")

# Function to fetch phishing URLs from OpenPhish
def fetch_openphish_feed():
    api_url = "https://openphish.com/feed.txt"
    try:
        print(f"Fetching phishing URLs from {api_url}")
        response = requests.get(api_url)
        print(f"Response Status Code: {response.status_code}")
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            print(f"Fetched {len(phishing_urls)} URLs from OpenPhish.")
            return phishing_urls
        else:
            print(f"Failed to fetch URLs. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching phishing URLs: {e}")
    return []

# Function to store URLs into the database and update phished_urls_set
def store_phishing_urls(phishing_urls):
    global phished_urls_set
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    count = 0
    try:
        for url in phishing_urls:
            source = "OpenPhish"
            category = "Unknown"
            detection_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
            INSERT INTO phished_urls (url, source, category, detection_date)
            VALUES (?, ?, ?, ?)
            ''', (url, source, category, detection_date))
            phished_urls_set.add(url)  # Add URL to in-memory set
            count += 1
    except Exception as e:
        print(f"Error storing URLs: {e}")
    conn.commit()
    conn.close()
    print(f"Inserted {count} URLs into the database.")
    return count

# Enhanced phishing detection logic
def is_phishing_url(url):
    """
    Enhanced phishing detection function.
    :param url: The URL to check.
    :return: 'Phishing' or 'Safe'
    """
    # Check if the URL is in the phished URLs set
    if url in phished_urls_set:
        return 'Phishing'

    # Extract domain from URL
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # Check for suspicious patterns in the URL
    suspicious_keywords = ["login", "secure", "account", "update", "register", "password"]
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        return 'Phishing'

    # Check for numeric IP address in the domain
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        return 'Phishing'

    # Check for very short or long domains
    if len(domain) < 5 or len(domain) > 50:
        return 'Phishing'

    # Check if the domain has suspicious subdomains (e.g., "secure.paypal.fake.com")
    if domain.count('.') > 2:
        return 'Phishing'

    return 'Safe'

# Generate a fake phishing URL
def generate_fake_url():
    return "/fake_login"  # Redirects to the fake login page


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    """
    API endpoint to check if a URL is phishing or safe.
    """
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = is_phishing_url(url)
    return jsonify({'url': url, 'result': result})

@app.route('/update_phished_urls', methods=['GET'])
def update_phished_urls():
    """
    Endpoint to fetch phishing URLs from OpenPhish and store them in the database.
    """
    phishing_urls = fetch_openphish_feed()
    if not phishing_urls:
        return jsonify({'error': 'Failed to fetch phishing URLs.'}), 500

    inserted_count = store_phishing_urls(phishing_urls)
    return jsonify({'message': f'{inserted_count} phishing URLs inserted into the database.'})

@app.route('/simulation', methods=['GET', 'POST'])
def simulation():
    """
    Phishing simulation page for managers to generate fake phishing URLs.
    """
    if request.method == 'POST':
        fake_url = generate_fake_url()
        return jsonify({"fake_url": fake_url})

    return render_template('simulation.html')

@app.route('/record_click', methods=['POST'])
def record_click():
    """
    Endpoint to record email IDs of users who clicked the fake phishing link.
    """
    email_id = request.json.get('email_id')
    if email_id and email_id not in clicked_emails:
        clicked_emails.append(email_id)
    return jsonify({"message": "Click recorded successfully", "clicked_emails": clicked_emails})

@app.route('/get_clicked_emails', methods=['GET'])
def get_clicked_emails():
    """
    Endpoint to fetch all clicked email IDs for the manager.
    """
    return jsonify({"clicked_emails": clicked_emails})
@app.route('/fake_login', methods=['GET'])
def fake_login():
    """
    Serve the fake login page.
    """
    return render_template('fake_login.html')


if __name__ == '__main__':
    init_db()
    # Fetch phishing URLs from the API and store them in memory on app start
    phishing_urls = fetch_openphish_feed()
    store_phishing_urls(phishing_urls)
    app.run(debug=True)
