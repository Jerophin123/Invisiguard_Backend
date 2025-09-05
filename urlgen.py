import sqlite3
import random
from datetime import datetime

# Connect to the existing database
conn = sqlite3.connect('phished_urls.db')
cursor = conn.cursor()

# Define phishing categories
categories = {
    "Urgency": ["urgent", "verify", "action_required", "account_blocked", "login_immediately", "expired"],
    "Reward": ["prize", "giftcard", "winner", "bonus_offer", "lotterywin", "special_reward"],
    "Technical": ["helpdesk", "it-support", "admin_reset", "maintenance_required", "security_patch"],
    "Authority": ["bank_notice", "police_alert", "gov_updates", "court_notice", "tax_refund"]
}

# Helper function to generate a fake URL
def generate_url(category_keywords):
    domain_choices = ["secure-login.com", "account-update.net", "verify-info.org", "urgent-alert.info", "service-support.tech"]
    keyword = random.choice(category_keywords)
    domain = random.choice(domain_choices)
    random_number = random.randint(1000, 9999)
    return f"http://{domain}/{keyword}/{random_number}"

# Generate and insert 500 URLs
phishing_urls = []

for _ in range(500):
    phishing_type = random.choice(list(categories.keys()))
    keywords = categories[phishing_type]
    url = generate_url(keywords)

    source = "Synthetic Script"
    category = phishing_type
    detection_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    phishing_urls.append((url, source, category, detection_date))

# Insert into database
cursor.executemany('''
    INSERT INTO phished_urls (url, source, category, detection_date)
    VALUES (?, ?, ?, ?)
''', phishing_urls)

conn.commit()
conn.close()

print("✅ Successfully inserted 500 phishing URLs into phished_urls table.")
