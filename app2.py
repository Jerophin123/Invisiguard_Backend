import re
import sqlite3
import requests
import os
import joblib
from datetime import datetime
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle
import io

app = Flask(__name__)
CORS(app)

# -------------------- Config / Globals --------------------
DB_NAME = "phished_urls.db"
phished_urls_set = set()
clicked_emails = []
UPLOAD_FOLDER = "./uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

HTTP_TIMEOUT = 10  # seconds for outbound requests

# -------------------- ML Model Load --------------------
try:
    spam_model = joblib.load('./ml_models/spam_detection_model.pkl')
    vectorizer = joblib.load('./ml_models/tfidf_vectorizer.pkl')
    print("Spam model and vectorizer loaded successfully.")
except Exception as e:
    print(f"Error loading spam detection model/vectorizer: {e}")
    spam_model = None
    vectorizer = None

# -------------------- DB Init --------------------
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

# -------------------- Data Sources --------------------
def fetch_openphish_feed():
    api_url = "https://openphish.com/feed.txt"
    try:
        response = requests.get(api_url, timeout=HTTP_TIMEOUT)
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

# -------------------- External Checks --------------------
def check_with_virustotal(url):
    # NOTE: do not hardcode API keys in code in production; use environment variables.
    api_key = os.getenv("VT_API_KEY", "")
    if not api_key:
        return "Unknown"

    try:
        headers = {"x-apikey": api_key}
        # Try to retrieve analysis id for this URL
        r = requests.post("https://www.virustotal.com/api/v3/urls",
                          headers=headers, data={"url": url}, timeout=HTTP_TIMEOUT)
        r.raise_for_status()
        url_id = r.json()["data"]["id"]

        # Fetch analysis summary
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        result = requests.get(analysis_url, headers=headers, timeout=HTTP_TIMEOUT)
        if result.status_code == 200:
            stats = result.json().get("data", {}).get("attributes", {}).get("stats", {})
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                return "Phishing"
        return "Safe"
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return "Unknown"

# -------------------- URL Heuristics --------------------
def is_phishing_url(url):
    url = url.lower().strip()
    if url.startswith("http:"):  # plain HTTP
        return "Phishing"

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.strip().lower()

    suspicious_keywords = [
        "login", "secure", "account", "update", "register", "password",
        "verify", "reset", "bank", "confirm", "signin", "security"
    ]

    verdicts = []

    # In-memory seen list
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

    # Keyword / shape checks
    if any(keyword in url for keyword in suspicious_keywords):
        verdicts.append("Phishing")

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):  # bare IP
        verdicts.append("Phishing")
    if len(domain) < 5 or len(domain) > 50:
        verdicts.append("Phishing")
    if domain.count('.') > 2:
        verdicts.append("Phishing")

    # VirusTotal
    vt_result = check_with_virustotal(url)
    if vt_result == "Phishing":
        verdicts.append("Phishing")

    return "Phishing" if "Phishing" in verdicts else "Safe"

# -------------------- Email Helpers --------------------
def extract_ip_from_email(file_path):
    try:
        with open(file_path, "rb") as file:
            msg = BytesParser(policy=policy.default).parse(file)
        headers = str(msg)
        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        ips = ip_pattern.findall(headers)
        return list(set(ips))
    except Exception as e:
        print(f"extract_ip_from_email error: {e}")
        return []

def get_ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=HTTP_TIMEOUT)
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

# -------------------- PDF Report --------------------
def generate_pdf_report(results, insights):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    margin = 40

    y = height - 50
    c.setFont("Helvetica-Bold", 20)
    c.drawString(180, y, "Spam Detection Report")
    y -= 40

    # File Analysis Table
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "■ File Analysis Results:")
    y -= 20

    data = [["Filename", "Result", "Accuracy (%)"]]
    for result in results:
        fname = result.get('filename', 'Unknown')
        short_filename = (fname[:15] + '...') if len(fname) > 15 else fname
        data.append([
            short_filename,
            result.get('spam_result', 'ERROR'),
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

    # IP Geolocation Table
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "■ IP and Geolocation Information:")
    y -= 20

    ip_data = [["Filename", "IP Address", "City", "Country"]]
    for result in results:
        fname = result.get('filename', 'Unknown')
        short_filename = (fname[:15] + '...') if len(fname) > 15 else fname
        for geo in result.get('geolocation_info', []):
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

    # Simple bar chart Spam vs Safe
    d = Drawing(400, 200)
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.height = 150
    chart.width = 300
    chart.data = [[insights.get('spam_files_detected', 0), insights.get('safe_files_detected', 0)]]
    chart.categoryAxis.categoryNames = ['Spam', 'Safe']
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(insights.get('spam_files_detected', 0),
                                   insights.get('safe_files_detected', 0), 1) + 2
    chart.valueAxis.valueStep = 1
    chart.barWidth = 30
    chart.groupSpacing = 10
    chart.barSpacing = 20
    chart.bars[0].fillColor = colors.red
    chart.bars[1].fillColor = colors.green
    d.add(chart)

    if y < 250:
        c.showPage()
        y = height - margin

    renderPDF.draw(d, c, margin, y - 200)

    c.setFont("Helvetica-Oblique", 8)
    c.drawCentredString(width / 2, 30, "Generated by Phishing & Spam Detection System © 2025")
    c.save()
    buffer.seek(0)
    return buffer

# -------------------- Safety Stub --------------------
def detect_phishing_personality(url: str):
    """
    Placeholder to avoid NameError from /api/check_url.
    Implement your real logic here if needed.
    """
    # Example: return a simple tag based on keywords
    if any(k in url for k in ("urgent", "verify", "reset", "security")):
        return "Urgency Phishing"
    if any(k in url for k in ("gift", "prize", "reward", "bonus")):
        return "Reward Phishing"
    return None

# -------------------- API ROUTES --------------------
@app.route('/api/check_url', methods=['POST'])
def api_check_url():
    data = request.get_json(silent=True) or {}
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = is_phishing_url(url)
    phishing_type = detect_phishing_personality(url) if result == 'Phishing' else None

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
    fake_url = generate_fake_url()
    return jsonify({"fake_url": fake_url})

@app.route('/api/record_click', methods=['POST'])
def api_record_click():
    data = request.get_json(silent=True) or {}
    email_id = data.get('email_id')
    if email_id and email_id not in clicked_emails:
        clicked_emails.append(email_id)
    return jsonify({"message": "Click recorded", "clicked_emails": clicked_emails})

@app.route('/api/get_clicked_emails', methods=['GET'])
def api_get_clicked_emails():
    return jsonify({"clicked_emails": clicked_emails})

@app.route('/fake_login', methods=['GET'])
def fake_login():
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
    # Ensure models are loaded
    if spam_model is None or vectorizer is None:
        return jsonify({'error': 'Spam model not available on server.'}), 500

    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    if not files or all(file.filename.strip() == '' for file in files):
        return jsonify({'error': 'No valid files selected'}), 400

    results = []
    total_files = 0
    spam_count = 0
    safe_count = 0

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            file.save(file_path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            email_features = vectorizer.transform([email_content])

            # Predict class and probability
            pred = spam_model.predict(email_features)[0]
            spam_result = "SPAM" if int(pred) == 1 else "NOT SPAM"

            if hasattr(spam_model, "predict_proba"):
                probabilities = spam_model.predict_proba(email_features)[0]
                confidence_score = round(float(max(probabilities)) * 100, 2)
            else:
                confidence_score = None

            ips = extract_ip_from_email(file_path)

            geo_results = []
            for ip in ips:
                geo_info = get_ip_geolocation(ip)
                # include only items that have coordinates
                if geo_info.get('lat') is not None and geo_info.get('lon') is not None:
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
            # Always return a consistent shape to avoid frontend crashes
            results.append({
                'filename': file.filename,
                'spam_result': 'ERROR',
                'confidence_score': None,
                'extracted_ips': [],
                'geolocation_info': [],
                'error': str(e)
            })
        finally:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass

    spam_percentage = round((spam_count / total_files) * 100, 2) if total_files else 0
    safe_percentage = round((safe_count / total_files) * 100, 2) if total_files else 0

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
    if spam_model is None or vectorizer is None:
        return jsonify({'error': 'Spam model not available on server.'}), 500

    if 'files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400

    files = request.files.getlist('files')
    results = []
    total_files = 0
    spam_count = 0
    safe_count = 0

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        try:
            file.save(file_path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            email_features = vectorizer.transform([email_content])
            prediction = spam_model.predict(email_features)[0]
            spam_result = "SPAM" if int(prediction) == 1 else "NOT SPAM"

            if hasattr(spam_model, "predict_proba"):
                probabilities = spam_model.predict_proba(email_features)[0]
                confidence_score = round(float(max(probabilities)) * 100, 2)
            else:
                confidence_score = None

            ips = extract_ip_from_email(file_path)
            geo_results = []
            for ip in ips:
                geo_info = get_ip_geolocation(ip)
                if geo_info.get('lat') is not None and geo_info.get('lon') is not None:
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
                'spam_result': 'ERROR',
                'confidence_score': None,
                'extracted_ips': [],
                'geolocation_info': [],
                'error': str(e)
            })
        finally:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass

    spam_percentage = round((spam_count / total_files) * 100, 2) if total_files else 0
    safe_percentage = round((safe_count / total_files) * 100, 2) if total_files else 0

    insights = {
        'total_files_analyzed': total_files,
        'spam_files_detected': spam_count,
        'safe_files_detected': safe_count,
        'spam_percentage': spam_percentage,
        'safe_percentage': safe_percentage
    }

    pdf_report = generate_pdf_report(results, insights)
    return send_file(
        pdf_report,
        as_attachment=True,
        download_name='spam_detection_report.pdf',
        mimetype='application/pdf'
    )

# -------------------- Main --------------------
if __name__ == '__main__':
    init_db()
    phishing_urls = fetch_openphish_feed()
    store_phishing_urls(phishing_urls)
    app.run(debug=True)
