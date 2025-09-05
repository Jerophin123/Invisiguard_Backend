import sqlite3
import requests

# Database setup
DB_NAME = "phished_urls.db"

def init_db():
    """Initialize the database and create the necessary table."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS phished_urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL UNIQUE  -- Ensure unique URLs
    )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized and ready.")

def fetch_openphish_feed():
    """Fetch phishing URLs from the OpenPhish feed."""
    api_url = "https://openphish.com/feed.txt"
    try:
        print(f"Fetching phishing URLs from {api_url}")
        response = requests.get(api_url, timeout=10)  # Added timeout for reliability
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            print(f"Fetched {len(phishing_urls)} URLs from OpenPhish.")
            return phishing_urls
        else:
            print(f"Failed to fetch URLs. Status code: {response.status_code}")
            return []
    except requests.exceptions.RequestException as e:
        print(f"Error fetching phishing URLs: {e}")
        return []

def store_phishing_urls(phishing_urls):
    """Store phishing URLs in the database."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    count = 0
    try:
        for url in phishing_urls:
            try:
                cursor.execute('''
                INSERT INTO phished_urls (url)
                VALUES (?)
                ''', (url,))  # Corrected to use a tuple
                count += 1
            except sqlite3.IntegrityError:
                # Skip duplicate URLs
                print(f"Duplicate URL skipped: {url}")
        conn.commit()
        print(f"Inserted {count} URLs into the database.")
    except sqlite3.DatabaseError as e:
        print(f"Error storing URLs: {e}")
    finally:
        conn.close()
    return count

def update_phished_urls():
    """Retrieve phishing URLs and store them in the database."""
    print("Starting update of phishing URLs...")
    phishing_urls = fetch_openphish_feed()
    if not phishing_urls:
        print("No URLs retrieved. Exiting.")
        return
    
    inserted_count = store_phishing_urls(phishing_urls)
    print(f"Update completed. {inserted_count} new phishing URLs added to the database.")

if __name__ == "__main__":
    init_db()
    update_phished_urls()
