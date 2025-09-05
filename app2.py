import random
import re
import sqlite3
import requests
import os
import socket
import joblib
from datetime import datetime
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
import io
from flask import send_file

app = Flask(__name__)
CORS(app)

# Database setup
DB_NAME = "phished_urls.db"
phished_urls_set = set()
clicked_emails = []
UPLOAD_FOLDER = "./uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Spam detection ML model
try:
    spam_model = joblib.load('./ml_models/spam_detection_model.pkl')
    vectorizer = joblib.load('./ml_models/tfidf_vectorizer.pkl')
    print("Spam model and vectorizer loaded successfully.")
except Exception as e:
    print(f"Error loading spam detection model/vectorizer: {e}")
    spam_model = None
    vectorizer = None

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
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS fake_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        submission_time TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized.")

def fetch_openphish_feed():
    api_url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            return response.text.splitlines()
    except Exception as e:
        print(f"Error fetching OpenPhish feed: {e}")
    return []

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
            phished_urls_set.add(url)
            count += 1
    except Exception as e:
        print(f"Error storing URLs: {e}")
    conn.commit()
    conn.close()
    return count

def check_with_virustotal(url):
    try:
        api_key = "118ae06a71ab66361e57900a6e9859911458c4b4effb8a6f4dabd969a386bd49"
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls", 
                                headers=headers,
                                params={"url": url})
        
        # If not already analyzed, we must submit the URL for scanning
        if response.status_code == 404:
            submission = requests.post("https://www.virustotal.com/api/v3/urls", 
                                       headers=headers,
                                       data={"url": url})
            url_id = submission.json()["data"]["id"]
        else:
            url_id = response.json()["data"]["id"]

        # Retrieve analysis report
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        result = requests.get(analysis_url, headers=headers)
        if result.status_code == 200:
            stats = result.json()["data"]["attributes"]["stats"]
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                return "Phishing"
        return "Safe"
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return "Unknown"


def is_phishing_url(url):
    url = url.lower().strip()
    
    # 🚨 Rule: Immediately flag if URL uses plain HTTP
    if url.startswith("http:"):
        return "Phishing"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.strip().lower()

    suspicious_keywords = [
        "login", "secure", "account", "update", "register", "password",
        "verify", "reset", "bank", "confirm", "signin", "security"
    ]

    verdicts = []

    # Memory check
    if any(phished_url in url for phished_url in phished_urls_set):
        verdicts.append("Phishing")

    # DB check
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT 1 FROM phished_urls WHERE url LIKE ?", (f"%{url}%",))
        result = cursor.fetchone()
        if result:
            verdicts.append("Phishing")
    except Exception as e:
        print(f"DB query error: {e}")
    conn.close()

    # Keyword check
    if any(keyword in url for keyword in suspicious_keywords):
        verdicts.append("Phishing")

    # IP and length check
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        verdicts.append("Phishing")
    if len(domain) < 5 or len(domain) > 50:
        verdicts.append("Phishing")
    if domain.count('.') > 2:
        verdicts.append("Phishing")

    # VirusTotal check
    vt_result = check_with_virustotal(url)
    if vt_result == "Phishing":
        verdicts.append("Phishing")

    return "Phishing" if "Phishing" in verdicts else "Safe"



def analyze_email_spam_local(email_content):
    try:
        email_features = vectorizer.transform([email_content]).toarray()
        prediction = spam_model.predict(email_features)
        confidence = spam_probabilities[predicted_label] * 10
        return "SPAM" if prediction[0] == 1 else "NOT SPAM"
    except Exception as e:
        return f"Error: {e}"

def extract_ip_from_email(file_path):
    try:
        with open(file_path, "rb") as file:
            msg = BytesParser(policy=policy.default).parse(file)
        headers = str(msg)
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        ips = ip_pattern.findall(headers)
        return list(set(ips))
    except Exception as e:
        return []

def get_ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            lat = data.get('lat')
            lon = data.get('lon')

            google_maps_link = None
            if lat is not None and lon is not None:
                google_maps_link = f"https://www.google.com/maps?q={lat},{lon}"

            return {
                "ip": ip,
                "country": data.get('country', 'Unknown'),
                "city": data.get('city', 'Unknown'),
                "lat": lat,
                "lon": lon,
                "isp": data.get('isp', 'Unknown'),
                "google_maps_link": google_maps_link
            }
    except Exception as e:
        print(f"Error fetching geolocation: {e}")
    return {
        "ip": ip,
        "country": "Unknown",
        "city": "Unknown",
        "lat": None,
        "lon": None,
        "isp": "Unknown",
        "google_maps_link": None
    }


def generate_fake_url():
    return "/fake_login"

import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF

def generate_pdf_report(results, insights):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 40

    y = height - 50
    c.setFont("Helvetica-Bold", 20)
    c.drawString(180, y, "Spam Detection Report")
    y -= 40

    ## ------------------------- ##
    ## File Analysis Table
    ## ------------------------- ##
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "■ File Analysis Results:")
    y -= 20

    data = [["Filename", "Result", "Accuracy (%)"]]
    for result in results:
        short_filename = result['filename'][:15] + '...' if len(result['filename']) > 15 else result['filename']
        data.append([
            short_filename,
            result['spam_result'],
            f"{result.get('confidence_score', 'N/A')}"
        ])

    table = Table(data, colWidths=[180, 100, 100])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('ALIGN', (1,1), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    table.wrapOn(c, width, height)
    table.drawOn(c, 50, y - (20 * len(data)))
    y -= (25 * len(data))

    ## ------------------------- ##
    ## IP Geolocation Table
    ## ------------------------- ##
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "■ IP and Geolocation Information:")
    y -= 20

    ip_data = [["Filename", "IP Address", "City", "Country"]]
    for result in results:
        short_filename = result['filename'][:15] + '...' if len(result['filename']) > 15 else result['filename']
        for geo in result['geolocation_info']:
            ip_data.append([
                short_filename,
                geo.get('ip', 'N/A'),
                geo.get('city', 'Unknown'),
                geo.get('country', 'Unknown')
            ])

    if len(ip_data) > 1:
        table = Table(ip_data, colWidths=[150, 100, 100, 100])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('ALIGN', (1,1), (-1,-1), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        table.wrapOn(c, width, height)
        table.drawOn(c, 50, y - (20 * len(ip_data)))
        y -= (25 * len(ip_data))

    # Bar Chart
    d = Drawing(400, 200)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.height = 150
    chart.width = 300
    chart.data = [[insights['spam_files_detected'], insights['safe_files_detected']]]

    chart.categoryAxis.categoryNames = ['Spam', 'Safe']
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(insights['spam_files_detected'], insights['safe_files_detected'], 1) + 2
    chart.valueAxis.valueStep = 1

    chart.barWidth = 30
    chart.groupSpacing = 10
    chart.barSpacing = 20

    # Coloring Bars
    chart.bars[0].fillColor = colors.red   # ✅ correct
    chart.bars[1].fillColor = colors.green # ✅ correct

    d.add(chart)

    # Check if enough space for chart
    if y < 250:
        c.showPage()
        y = height - margin

    renderPDF.draw(d, c, margin, y - 200)

    # Footer
    c.setFont("Helvetica-Oblique", 8)
    c.drawCentredString(width / 2, 30, "Generated by Phishing & Spam Detection System © 2025")

    # Save and Return
    c.save()
    buffer.seek(0)
    return buffer



# ---------- API ROUTES ----------


@app.route('/api/check_url', methods=['POST'])
def api_check_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = is_phishing_url(url)

    # Personality Detector Part:
    phishing_type = None
    if result == 'Phishing':
        phishing_type = detect_phishing_personality(url)

    return jsonify({
        'url': url,
        'result': result,
        'phishing_type': phishing_type
    })


@app.route('/api/update_phished_urls', methods=['POST'])
def api_update_phished_urls():
    phishing_urls = fetch_openphish_feed()
    if not phishing_urls:
        return jsonify({'error': 'Failed to fetch URLs.'}), 500
    inserted_count = store_phishing_urls(phishing_urls)
    return jsonify({'message': f'{inserted_count} phishing URLs inserted.'})

@app.route('/api/generate_fake_url', methods=['GET'])
def api_generate_fake_url():
    fake_url = "/fake_login"
    return jsonify({"fake_url": fake_url})

@app.route('/api/record_click', methods=['POST'])
def api_record_click():
    data = request.get_json()
    email_id = data.get('email_id')
    if email_id and email_id not in clicked_emails:
        clicked_emails.append(email_id)
    return jsonify({"message": "Click recorded", "clicked_emails": clicked_emails})

@app.route('/api/get_clicked_emails', methods=['GET'])
def api_get_clicked_emails():
    return jsonify({"clicked_emails": clicked_emails})

@app.route('/fake_login', methods=['GET'])
def fake_login():
    """
    Serve the fake login page.
    """
    return render_template('fake_login.html')

@app.route('/submit_credentials', methods=['POST'])
def submit_credentials():
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        submission_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute('''
        INSERT INTO fake_credentials (email, password, submission_time)
        VALUES (?, ?, ?)
        ''', (email, password, submission_time))
        conn.commit()
    except Exception as e:
        print(f"Error inserting credentials: {e}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

    return jsonify({'message': 'Credentials stored successfully'})


@app.route('/api/check_spam', methods=['POST'])
def api_check_spam():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    if not files or all(file.filename == '' for file in files):
        return jsonify({'error': 'No valid files selected'}), 400

    results = []
    total_files = 0
    spam_count = 0
    safe_count = 0

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            email_features = vectorizer.transform([email_content]).toarray()

            # Predict class and probability
            prediction = spam_model.predict(email_features)[0]
            spam_result = "SPAM" if prediction == 1 else "NOT SPAM"

            if hasattr(spam_model, "predict_proba"):
                probabilities = spam_model.predict_proba(email_features)[0]
                confidence_score = round(max(probabilities) * 100, 2)  # Highest probability
            else:
                confidence_score = None  # If model doesn't support it

            ips = extract_ip_from_email(file_path)

            # Fetch only IPs with valid lat/lon
            geo_results = []
            for ip in ips:
                geo_info = get_ip_geolocation(ip)
                if geo_info.get('lat') not in [None, 'Unknown'] and geo_info.get('lon') not in [None, 'Unknown']:
                    geo_info['google_maps_link'] = f"https://www.google.com/maps?q={geo_info['lat']},{geo_info['lon']}"
                    geo_results.append(geo_info)

            # Count results
            total_files += 1
            if spam_result == 'SPAM':
                spam_count += 1
            else:
                safe_count += 1

            results.append({
                'filename': file.filename,
                'spam_result': spam_result,
                'confidence_score': confidence_score,
                'extracted_ips': [geo['ip'] for geo in geo_results],
                'geolocation_info': geo_results
            })

        except Exception as e:
            results.append({
                'filename': file.filename,
                'error': str(e)
            })

        finally:
            os.remove(file_path)

    # Calculate accuracy based on classification
    if total_files > 0:
        spam_percentage = round((spam_count / total_files) * 100, 2)
        safe_percentage = round((safe_count / total_files) * 100, 2)
    else:
        spam_percentage = 0
        safe_percentage = 0
    

    return jsonify({
        'status': 'success',
        'results': results,
        'insights': {
            'total_files_analyzed': total_files,
            'spam_files_detected': spam_count,
            'safe_files_detected': safe_count,
            'spam_percentage': spam_percentage,
            'safe_percentage': safe_percentage
        }
    })

@app.route('/api/generate_pdf_report', methods=['POST'])
def api_generate_pdf_report():
    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')

    results = []
    total_files = 0
    spam_count = 0
    safe_count = 0

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            email_features = vectorizer.transform([email_content]).toarray()
            prediction = spam_model.predict(email_features)[0]
            spam_result = "SPAM" if prediction == 1 else "NOT SPAM"

            if hasattr(spam_model, "predict_proba"):
                probabilities = spam_model.predict_proba(email_features)[0]
                confidence_score = round(max(probabilities) * 100, 2)
            else:
                confidence_score = None

            ips = extract_ip_from_email(file_path)

            geo_results = []
            for ip in ips:
                geo_info = get_ip_geolocation(ip)
                if geo_info.get('lat') not in [None, 'Unknown'] and geo_info.get('lon') not in [None, 'Unknown']:
                    geo_info['google_maps_link'] = f"https://www.google.com/maps?q={geo_info['lat']},{geo_info['lon']}"
                    geo_results.append(geo_info)

            total_files += 1
            if spam_result == 'SPAM':
                spam_count += 1
            else:
                safe_count += 1

            results.append({
                'filename': file.filename,
                'spam_result': spam_result,
                'confidence_score': confidence_score,
                'extracted_ips': [geo['ip'] for geo in geo_results],
                'geolocation_info': geo_results
            })

        except Exception as e:
            results.append({
                'filename': file.filename,
                'error': str(e)
            })

        finally:
            os.remove(file_path)

    if total_files > 0:
        spam_percentage = round((spam_count / total_files) * 100, 2)
        safe_percentage = round((safe_count / total_files) * 100, 2)
    else:
        spam_percentage = 0
        safe_percentage = 0

    insights = {
        'total_files_analyzed': total_files,
        'spam_files_detected': spam_count,
        'safe_files_detected': safe_count,
        'spam_percentage': spam_percentage,
        'safe_percentage': safe_percentage
    }

    # Now you have both 'results' and 'insights' ready ✅

    pdf_report = generate_pdf_report(results, insights)

    return send_file(
        pdf_report,
        as_attachment=True,
        download_name='spam_detection_report.pdf',
        mimetype='application/pdf'
    )
# ---------- END API ROUTES ----------

if __name__ == '__main__':
    init_db()
    phishing_urls = fetch_openphish_feed()
    store_phishing_urls(phishing_urls)
    app.run(debug=True)
    